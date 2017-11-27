// Copyright 2017 Google Inc. All Rights Reserved.
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

package resetserver

import (
	"context"
	"crypto"
	"errors"
	"fmt"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/google/keytransparency/core/adminstorage"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

var (
	// ErrRetry occurs when an update request has been submitted, but the
	// results of the update are not visible on the server yet. The client
	// must retry until the request is visible.
	ErrRetry = errors.New("update not present on server yet")
)

// batch holds a single batch operation
type batch struct {
	tmap    trillian.TrillianMapClient
	storage mutator.MutationStorage
	factory transaction.Factory

	domain  *adminstorage.Domain
	vrfKey  crypto.PrivateKey
	indexes map[string]Account
}

// Account puts a UserID and Profile together.
type Account struct {
	data     []byte
	authKeys []*keyspb.PublicKey

	mutation      *entry.Mutation
	update        *pb.EntryUpdate
	updateApplied bool
	err           error
}

// NewBatch creates a new batch operation. Only one domain is allowed.
func (s *server) NewBatch(ctx context.Context, accounts []*pb.Account) (*batch, error) {
	if got, want := len(accounts), 1; got < want {
		return nil, fmt.Errorf("NewBatch with %d accounts, want > %d", got, want)
	}

	// The whole batch must have the same domain_id.
	domainID := accounts[0].GetDomainId()
	for _, a := range accounts {
		if got, want := a.DomainId, domainID; got != want {
			return nil, fmt.Errorf("whole batch must have same domain_id. Got %v, want %v", got, want)
		}
	}

	// Read domain info.
	domain, err := s.admin.Read(ctx, domainID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", domainID, err)
		return nil, grpc.Errorf(codes.NotFound, "Cannot fetch domain info")
	}
	vrfPriv, err := p256.NewFromWrappedKey(ctx, domain.VRFPriv)
	if err != nil {
		return nil, err
	}

	return &batch{
		tmap:    s.tmap,
		storage: s.storage,
		factory: s.factory,

		domain:  domain,
		vrfKey:  vrfPriv,
		indexes: makeAccountMap(accounts, vrfPriv),
	}, nil
}

func makeAccountMap(accounts []*pb.Account, vrfPriv vrf.PrivateKey) map[string]Account {
	indexes := make(map[string]Account)
	for _, a := range accounts {
		index, _ := vrfPriv.Evaluate(vrf.UniqueID(a.UserId, a.AppId))
		idx := index[:]
		indexes[string(idx)] = Account{
			data:     a.Data,
			authKeys: a.AuthorizedKeys,
			mutation: entry.NewMutation(idx, a.UserId, a.AppId),
		}
	}
	return indexes
}

// GetLeaves fills in the oldLeaf field
func (b *batch) GetLeaves(ctx context.Context) error {
	indexes := make([][]byte, 0, len(b.indexes))
	for i := range b.indexes {
		indexes = append(indexes, []byte(i))
	}
	// Batch read existing values from map.
	getResp, err := b.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId:    b.domain.MapID,
		Index:    indexes,
		Revision: -1, // Get latest revision.
	})
	if err != nil {
		return err
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		return fmt.Errorf("map returned %d leaves, want %d", got, want)
	}

	for _, incl := range getResp.GetMapLeafInclusion() {
		leafIndex := incl.GetLeaf().GetIndex()
		a, ok := b.indexes[string(leafIndex)]
		if !ok {
			return fmt.Errorf("User for index %x not found", leafIndex)
		}
		if err := a.mutation.SetPrevious(incl.GetLeaf().GetLeafValue()); err != nil {
			return fmt.Errorf("mutation.SetPrevious(): %v", err)
		}
	}
	return nil
}

// Verify requeries the map and verifies that the changes requested were applied.
// TODO: pull out a function for operating on data returned from the server.
func (b *batch) Verify(ctx context.Context) error {
	indexes := make([][]byte, 0, len(b.indexes))
	for i := range b.indexes {
		indexes = append(indexes, []byte(i))
	}
	// Batch read existing values from map.
	getResp, err := b.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId:    b.domain.MapID,
		Index:    indexes,
		Revision: -1, // Get latest revision.
	})
	if err != nil {
		return err
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		return fmt.Errorf("map returned %d leaves, want %d", got, want)
	}

	for _, incl := range getResp.GetMapLeafInclusion() {
		leafIndex := incl.GetLeaf().GetIndex()
		a, ok := b.indexes[string(leafIndex)]
		if !ok {
			return fmt.Errorf("User for index %x not found", leafIndex)
		}

		leafValue, err := entry.FromLeafValue(incl.GetLeaf().GetLeafValue())
		if err != nil {
			a.err = fmt.Errorf("failed to decode current entry: %v", err)
			continue
		}

		if got, want := leafValue, a.update.GetMutation(); !proto.Equal(got, want) {
			a.err = ErrRetry
		}
	}
	return nil
}

// SetProfiles converts a map from names and profiles to a list
func (b *batch) SetData() {
	for _, a := range b.indexes {
		if err := a.mutation.SetCommitment(a.data); err != nil {
			a.err = err
		}
	}
}

// SetAuthorizedKeys replaces each account's authorized keys with its authorized keys.
func (b *batch) SetAuthorizedKeys() {
	for _, a := range b.indexes {
		// TODO(gbelvin) should we check a.err before trying any new operations?
		if err := a.mutation.ReplaceAuthorizedKeys(a.authKeys); err != nil {
			a.err = err
		}
	}
}

// SignMutations returns the list of updates.
func (b *batch) SignMutations(signers []signatures.Signer) {
	for _, a := range b.indexes {
		// Sign Entry
		update, err := a.mutation.SerializeAndSign(signers)
		if err != nil {
			a.err = err
		}
		a.update = update
	}
}

// SaveMutations writes the mutations to the list of mutations
func (b *batch) SaveMutations(ctx context.Context) error {
	// Collect mutations
	mutations := make([]*pb.EntryUpdate, 0, len(b.indexes))
	for _, u := range b.indexes {
		// TODO(gbelvin): skip nill updates?
		mutations = append(mutations, u.update)
	}

	// Store the update requests.
	txn, err := b.factory.NewTxn(ctx)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Cannot create transaction")
	}
	maxSeq, err := b.storage.BulkWrite(txn, b.domain.MapID, mutations)
	if err != nil {
		return err
	}
	if err := txn.Commit(); err != nil {
		glog.Errorf("Cannot commit transaction: %v", err)
		return grpc.Errorf(codes.Internal, "Cannot commit transaction: %v", err)
	}
	return nil
}
