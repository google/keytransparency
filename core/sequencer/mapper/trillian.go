// Copyright 2018 Google Inc. All Rights Reserved.
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

package mapper

import (
	"context"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

// ClientFactory creates TrilianClients for particular directories.
type ClientFactory struct {
	tmap        tpb.TrillianMapClient
	mapAdmin    tpb.TrillianAdminClient
	directories directory.Storage
}

// NewClientFactory returns a ClientFactory
func NewClientFactory(
	tmap tpb.TrillianMapClient,
	mapAdmin tpb.TrillianAdminClient,
	directories directory.Storage,
) *ClientFactory {
	return &ClientFactory{
		tmap:        tmap,
		mapAdmin:    mapAdmin,
		directories: directories,
	}
}

// MakeMapClient returns a MapClient
func (f *ClientFactory) MakeMapClient(ctx context.Context, dirID string) (*MapClient, error) {
	directory, err := f.directories.Read(ctx, dirID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", dirID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info for %v", dirID)
	}
	mapTree, err := f.mapAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: directory.MapID})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Cannot fetch map info for %v: %v", dirID, err)
	}
	c, err := tclient.NewMapClientFromTree(f.tmap, mapTree)
	if err != nil {
		return nil, err
	}
	return &MapClient{
		MapClient: c,
	}, nil
}

// MapClient wraps a trillian MapClient so we can add unimplemented verification methods.
// TODO(gbelvin): Move to Trillian Map client.
type MapClient struct {
	*tclient.MapClient
}

// SetLeaves creates a new map revision and returns its verified root.
func (c *MapClient) SetLeaves(ctx context.Context, leaves []*tpb.MapLeaf, metadata []byte) (*types.MapRootV1, error) {
	// Set new leaf values.
	setResp, err := c.Conn.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		MapId:    c.MapID,
		Leaves:   leaves,
		Metadata: metadata,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmap.SetLeaves(): %v", err)
	}
	mapRoot, err := c.VerifySignedMapRoot(setResp.GetMapRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	return mapRoot, nil
}
