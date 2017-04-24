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

// Package mapserver implements the TrillianMapClient interface.
// To start with, this will use KT's internal utilities to accomplish the same functions.
// Later this will be replaced with a simple RPC to Trillian Maps.
package mapserver

import (
	"crypto"
	"fmt"
	"log"

	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/core/tree"
	"github.com/google/trillian"

	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/util"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// mapServer implements TrilianMap functionality.
type mapServer struct {
	mapID   int64
	tree    tree.Sparse
	factory transaction.Factory
	sths    appender.Local
	signer  *tcrypto.Signer
	clock   util.TimeSource
}

// New returns a TrillianMapClient.
func New(mapID int64, tree tree.Sparse, factory transaction.Factory, sths appender.Local,
	signer crypto.Signer, clock util.TimeSource) trillian.TrillianMapClient {
	return &mapServer{
		mapID:   mapID,
		tree:    tree,
		factory: factory,
		sths:    sths,
		signer:  tcrypto.NewSHA256Signer(signer),
		clock:   clock,
	}
}

func (m *mapServer) signRoot(ctx context.Context) (smr *trillian.SignedMapRoot, retErr error) {
	txn, err := m.factory.NewTxn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if rbErr := txn.Rollback(); rbErr != nil {
				retErr = fmt.Errorf("%v, Rollback(): %v", retErr, rbErr)
			}
		}
	}()

	if err := m.tree.Commit(txn); err != nil {
		return nil, fmt.Errorf("Commit(): %v", err)
	}
	epoch, err := m.tree.Epoch(txn)
	if err != nil {
		return nil, fmt.Errorf("Epoch(): %v", err)
	}
	root, err := m.tree.ReadRootAt(txn, epoch)
	if err != nil {
		return nil, fmt.Errorf("ReadRootAt(%v): %v", epoch, err)
	}

	smr = &trillian.SignedMapRoot{
		MapId:          m.mapID,
		MapRevision:    epoch,
		RootHash:       root,
		TimestampNanos: m.clock.Now().Unix(),
		// TODO: Add mutation high watermark?
	}
	sig, err := m.signer.SignObject(smr)
	if err != nil {
		return nil, err
	}
	smr.Signature = sig

	// Save signed map head.
	if err := m.sths.Write(txn, m.mapID, epoch, smr); err != nil {
		return nil, fmt.Errorf("Append SMH failure %v", err)
	}
	if err := txn.Commit(); err != nil {
		return nil, err
	}

	log.Printf("Created epoch %v. SMH: %#x", epoch, root)
	return smr, nil
}

// SetLeaves adds the leaves and commits them in a single transaction, returning the new MapRoot.
func (m *mapServer) SetLeaves(ctx context.Context, in *trillian.SetMapLeavesRequest, opts ...grpc.CallOption) (resp *trillian.SetMapLeavesResponse, retErr error) {
	if got, want := in.MapId, m.mapID; got != want {
		return nil, fmt.Errorf("Wrong Map ID: %v, want %v", got, want)
	}
	txn, err := m.factory.NewTxn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if rbErr := txn.Rollback(); rbErr != nil {
				retErr = fmt.Errorf("%v, Rollback(): %v", retErr, rbErr)
			}
		}
	}()
	for _, l := range in.Leaves {
		if err := m.tree.QueueLeaf(txn, l.Index, l.LeafValue); err != nil {
			return nil, fmt.Errorf("QueueLeaf(): %v", err)
		}
	}
	if err := txn.Commit(); err != nil {
		return nil, err
	}

	smh, err := m.signRoot(ctx)
	if err != nil {
		return nil, fmt.Errorf("signRoot(): %v", err)
	}

	return &trillian.SetMapLeavesResponse{
		MapRoot: smh,
	}, nil
}

// GetLeaves returns the requested leaves.
func (m *mapServer) GetLeaves(ctx context.Context, in *trillian.GetMapLeavesRequest, opts ...grpc.CallOption) (resp *trillian.GetMapLeavesResponse, retErr error) {
	if got, want := in.MapId, m.mapID; got != want {
		return nil, fmt.Errorf("Wrong Map ID: %v, want %v", got, want)
	}

	txn, err := m.factory.NewTxn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if rbErr := txn.Rollback(); rbErr != nil {
				retErr = fmt.Errorf("%v, Rollback(): %v", retErr, rbErr)
			}
		}
	}()

	// Get current epoch.
	var root trillian.SignedMapRoot
	if _, err := m.sths.Latest(txn, in.MapId, &root); err != nil {
		return nil, err
	}

	// ReadLeavesAtEpoch.
	inclusions := make([]*trillian.MapLeafInclusion, 0, len(in.Index))
	for _, index := range in.Index {
		leafData, err := m.tree.ReadLeafAt(txn, index, root.MapRevision)
		if err != nil {
			return nil, err
		}
		nbrs, err := m.tree.NeighborsAt(txn, index, root.MapRevision)
		if err != nil {
			return nil, err
		}
		inclusions = append(inclusions, &trillian.MapLeafInclusion{
			Leaf: &trillian.MapLeaf{
				Index:     index,
				LeafValue: leafData,
			},
			Inclusion: nbrs,
		})
	}

	if err := txn.Commit(); err != nil {
		return nil, err
	}

	return &trillian.GetMapLeavesResponse{
		MapLeafInclusion: inclusions,
		MapRoot:          &root,
	}, nil
}

// GetSignedMapRoot returns the requested MapRoot.
func (m *mapServer) GetSignedMapRoot(ctx context.Context, in *trillian.GetSignedMapRootRequest, opts ...grpc.CallOption) (resp *trillian.GetSignedMapRootResponse, retErr error) {
	if got, want := in.MapId, m.mapID; got != want {
		return nil, fmt.Errorf("Wrong Map ID: %v, want %v", got, want)
	}

	txn, err := m.factory.NewTxn(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if rbErr := txn.Rollback(); rbErr != nil {
				retErr = fmt.Errorf("%v, Rollback(): %v", retErr, rbErr)
			}
		}
	}()

	// Get current epoch.
	var root trillian.SignedMapRoot
	if _, err := m.sths.Latest(txn, in.MapId, &root); err != nil {
		return nil, err
	}

	if err := txn.Commit(); err != nil {
		return nil, err
	}

	return &trillian.GetSignedMapRootResponse{
		MapRoot: &root,
	}, nil
}
