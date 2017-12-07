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

package fake

import (
	"context"

	"google.golang.org/grpc"

	tpb "github.com/google/trillian"
)

type mapServer struct {
	// roots by revision number
	roots    map[int64]*tpb.SignedMapRoot
	revision int64
}

// NewTrillianMapClient returns a fake tpb.TrillianMapClient
// This client only stores tpb.MapperMetadata in roots. It does not store
// leaves compute inclusion proofs, or sign roots.  This client is not
// threadsafe.
func NewTrillianMapClient() tpb.TrillianMapClient {
	m := &mapServer{
		roots: make(map[int64]*tpb.SignedMapRoot),
	}
	m.roots[0] = &tpb.SignedMapRoot{} // Set the initial root
	return m
}

// GetLeaves just returns the indexes requested. No leaf data, no inclusion proofs.
func (m *mapServer) GetLeaves(ctx context.Context, in *tpb.GetMapLeavesRequest, opts ...grpc.CallOption) (*tpb.GetMapLeavesResponse, error) {
	return m.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    in.MapId,
		Index:    in.Index,
		Revision: m.revision,
	}, opts...)
}

// GetLeavesByRevision just returns the indexes requested. No leaf data, no inclusion proofs.
func (m *mapServer) GetLeavesByRevision(ctx context.Context, in *tpb.GetMapLeavesByRevisionRequest, opts ...grpc.CallOption) (*tpb.GetMapLeavesResponse, error) {
	leaves := make([]*tpb.MapLeafInclusion, 0, len(in.Index))
	for _, index := range in.Index {
		leaves = append(leaves, &tpb.MapLeafInclusion{
			Leaf: &tpb.MapLeaf{
				Index: index,
			},
		})
	}
	return &tpb.GetMapLeavesResponse{
		MapLeafInclusion: leaves,
	}, nil
}

// SetLeaves is not thread safe. It will store the root metadata.
func (m *mapServer) SetLeaves(ctx context.Context, in *tpb.SetMapLeavesRequest, opts ...grpc.CallOption) (*tpb.SetMapLeavesResponse, error) {
	m.revision++
	m.roots[m.revision] = &tpb.SignedMapRoot{
		Metadata:    in.Metadata,
		MapRevision: m.revision,
	}
	return nil, nil
}

// GetSignedMapRootByRevision returns the current map root.
func (m *mapServer) GetSignedMapRoot(ctx context.Context, in *tpb.GetSignedMapRootRequest, opts ...grpc.CallOption) (*tpb.GetSignedMapRootResponse, error) {
	return m.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		Revision: m.revision,
	}, opts...)
}

// GetSignedMapRootByRevision returns the saved map root.
func (m *mapServer) GetSignedMapRootByRevision(ctx context.Context, in *tpb.GetSignedMapRootByRevisionRequest, opts ...grpc.CallOption) (*tpb.GetSignedMapRootResponse, error) {
	return &tpb.GetSignedMapRootResponse{
		MapRoot: m.roots[in.Revision],
	}, nil
}
