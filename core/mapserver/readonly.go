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

package mapserver

import (
	"fmt"

	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/core/tree"

	"github.com/google/trillian"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

// readonly implements a readonly mapserver frontend.
type readonly struct {
	mapID   int64
	tree    tree.Sparse
	factory transaction.Factory
	sths    appender.Local
}

// NewReadonly returns a readonly view of the sparse merkle tree.
func NewReadonly(mapID int64, tree tree.Sparse, factory transaction.Factory, sths appender.Local) trillian.TrillianMapClient {
	return &readonly{
		mapID:   mapID,
		tree:    tree,
		factory: factory,
		sths:    sths,
	}
}

func (r *readonly) GetLeaves(ctx context.Context, in *trillian.GetMapLeavesRequest, opts ...grpc.CallOption) (resp *trillian.GetMapLeavesResponse, retErr error) {
	// TODO: remove when multi-tennant maps are supported.
	if got, want := in.MapId, r.mapID; got != want {
		return nil, fmt.Errorf("Wrong Map ID: %v, want %v", got, want)
	}

	txn, err := r.factory.NewTxn(ctx)
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

	var root trillian.SignedMapRoot
	if in.Revision == -1 {
		// Get current epoch.
		if _, err := r.sths.Latest(txn, in.MapId, &root); err != nil {
			return nil, err
		}
	} else {
		if err := r.sths.Read(txn, in.MapId, in.Revision, &root); err != nil {
			return nil, err
		}
	}

	// ReadLeavesAtEpoch.
	inclusions := make([]*trillian.MapLeafInclusion, 0, len(in.Index))
	for _, index := range in.Index {
		leafData, err := r.tree.ReadLeafAt(txn, index, root.MapRevision)
		if err != nil {
			return nil, err
		}
		nbrs, err := r.tree.NeighborsAt(txn, index, root.MapRevision)
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

func (r *readonly) SetLeaves(ctx context.Context, in *trillian.SetMapLeavesRequest, opts ...grpc.CallOption) (*trillian.SetMapLeavesResponse, error) {
	panic("SetLeaves not implmeneted in read only object")
}

func (r *readonly) GetSignedMapRoot(ctx context.Context, in *trillian.GetSignedMapRootRequest, opts ...grpc.CallOption) (resp *trillian.GetSignedMapRootResponse, retErr error) {
	if got, want := in.MapId, r.mapID; got != want {
		return nil, fmt.Errorf("Wrong Map ID: %v, want %v", got, want)
	}

	txn, err := r.factory.NewTxn(ctx)
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
	if _, err := r.sths.Latest(txn, in.MapId, &root); err != nil {
		return nil, err
	}

	if err := txn.Commit(); err != nil {
		return nil, err
	}

	return &trillian.GetSignedMapRootResponse{
		MapRoot: &root,
	}, nil
}
