// Copyright 2016 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package signer

import (
	"fmt"
	"log"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"

	"github.com/google/trillian"
	"golang.org/x/net/context"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

// Signer processes mutations and sends them to the trillian map.
type Signer struct {
	realm     string
	mapID     int64
	tmap      trillian.TrillianMapClient
	logID     int64
	sths      appender.Remote
	mutator   mutator.Mutator
	mutations mutator.Mutation
	factory   transaction.Factory
}

// New creates a new instance of the signer.
func New(realm string,
	mapID int64,
	tmap trillian.TrillianMapClient,
	logID int64,
	sths appender.Remote,
	mutator mutator.Mutator,
	mutations mutator.Mutation,
	factory transaction.Factory) *Signer {
	return &Signer{
		realm:     realm,
		mapID:     mapID,
		tmap:      tmap,
		sths:      sths,
		mutator:   mutator,
		mutations: mutations,
		factory:   factory,
	}
}

// StartSigning advance epochs once per interval.
func (s *Signer) StartSigning(ctx context.Context, interval time.Duration) {
	for range time.NewTicker(interval).C {
		if err := s.CreateEpoch(ctx); err != nil {
			log.Fatalf("CreateEpoch failed: %v", err)
		}
	}
}

// newMutations returns a list of mutations to process and highest sequence number returned.
func (s *Signer) newMutations(ctx context.Context, startSequence int64) ([]*tpb.SignedKV, int64, error) {
	txn, err := s.factory.NewTxn(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("NewDBTxn(): %v", err)
	}

	maxSequence, mutations, err := s.mutations.ReadAll(txn, uint64(startSequence))
	if err != nil {
		if err := txn.Rollback(); err != nil {
			log.Printf("Cannot rollback the transaction: %v", err)
		}
		return nil, 0, fmt.Errorf("ReadAll(%v): %v", startSequence, err)
	}

	if err := txn.Commit(); err != nil {
		return nil, 0, fmt.Errorf("txn.Commit(): %v", err)
	}
	return mutations, int64(maxSequence), nil
}

// toArray returns the first 20 bytes from b.
// If b is less than 20 bytes long, the output is zero padded.
func toArray(b []byte) [20]byte {
	var i [20]byte
	copy(i[:], b)
	return i
}

// applyMutations takes the set of mutations and applies them to given leafs.
// Multiple mutations for the same leaf will be applied to provided leaf.
// The last valid mutation for each leaf is included in the output.
// Returns a list of map leaves that should be updated.
func (s *Signer) applyMutations(mutations []*tpb.SignedKV, leaves []*trillian.MapLeaf) ([]*trillian.MapLeaf, error) {
	// Put leaves in a map from index to leaf value.
	leafMap := make(map[[20]byte]*trillian.MapLeaf)
	for _, l := range leaves {
		leafMap[toArray(l.Index)] = l
	}

	retMap := make(map[[20]byte]*trillian.MapLeaf)
	for _, m := range mutations {
		index := m.GetKeyValue().Key
		var oldValue []byte // If no map leaf was found, oldValue will be nil.
		leaf, ok := leafMap[toArray(index)]
		if ok {
			oldValue = leaf.LeafValue
		}

		// TODO: change mutator interface to accept objects directly.
		mData, err := proto.Marshal(m)
		if err != nil {
			return nil, err
		}
		newValue, err := s.mutator.Mutate(oldValue, mData)
		if err != nil {
			log.Printf("Mutate(): %v", err)
			continue // A bad mutation should not make the whole batch fail.
		}

		retMap[toArray(index)] = &trillian.MapLeaf{
			Index:     index,
			LeafValue: newValue,
		}
	}
	// Convert return map back into a list.
	ret := make([]*trillian.MapLeaf, 0, len(retMap))
	for _, v := range retMap {
		ret = append(ret, v)
	}
	return ret, nil
}

// CreateEpoch signs the current map head.
func (s *Signer) CreateEpoch(ctx context.Context) error {
	// Get the current root.
	rootResp, err := s.tmap.GetSignedMapRoot(ctx, &trillian.GetSignedMapRootRequest{
		MapId: s.mapID,
	})
	if err != nil {
		return err
	}
	startSequence := rootResp.GetMapRoot().GetMetadata().GetHighestFullyCompletedSeq()

	// Get the list of new mutations to process.
	mutations, seq, err := s.newMutations(ctx, startSequence)
	if err != nil {
		return err
	}

	// Get current leaf values.
	indexes := make([][]byte, 0, len(mutations))
	for _, m := range mutations {
		indexes = append(indexes, m.KeyValue.Key)
	}
	getResp, err := s.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId: s.mapID,
		Index: indexes,
	})
	if err != nil {
		return err
	}

	// TODO: verify inclusion proofs?
	leaves := make([]*trillian.MapLeaf, 0, len(getResp.MapLeafInclusion))
	for _, m := range getResp.MapLeafInclusion {
		leaves = append(leaves, m.Leaf)
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(mutations, leaves)
	if err != nil {
		return err
	}

	// Set new leaf values.
	setResp, err := s.tmap.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
		MapId:  s.mapID,
		Leaves: newLeaves,
		MapperData: &trillian.MapperMetadata{
			HighestFullyCompletedSeq: seq,
		},
	})
	// Put SignedMapHead in an append only log.
	return s.sths.Write(ctx, s.logID, setResp.MapRoot.MapRevision, setResp.MapRoot)
}
