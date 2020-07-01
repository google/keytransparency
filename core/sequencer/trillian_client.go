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

package sequencer

import (
	"context"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/directory"

	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

// trillianFactory creates verifying clients for Trillian
type trillianFactory interface {
	MapClient(ctx context.Context, dirID string) (trillianMap, error)
	MapWriteClient(ctx context.Context, dirID string) (*MapWriteClient, error)
	LogClient(ctx context.Context, dirID string) (trillianLog, error)
}

// trillianMap communicates with the Trilian map and verifies the responses.
type trillianMap interface {
	GetAndVerifyLatestMapRoot(ctx context.Context) (*tpb.SignedMapRoot, *types.MapRootV1, error)
	GetAndVerifyMapRootByRevision(ctx context.Context, rev int64) (*tpb.SignedMapRoot, *types.MapRootV1, error)
}

// trillianLog communicates with the Trillian log and verifies the responses.
type trillianLog interface {
	WaitForInclusion(ctx context.Context, data []byte) error
	UpdateRoot(ctx context.Context) (*types.LogRootV1, error)
	AddSequencedLeaves(ctx context.Context, dataByIndex map[int64][]byte) error
}

// Trillian contains Trillian gRPC clients and metadata about them.
type Trillian struct {
	directories directory.Storage
	tmap        tpb.TrillianMapClient
	tlog        tpb.TrillianLogClient
	twrite      tpb.TrillianMapWriteClient
}

// MapWriteClient returns a connection to the map write API.
func (t *Trillian) MapWriteClient(ctx context.Context, dirID string) (*MapWriteClient, error) {
	directory, err := t.directories.Read(ctx, dirID, false)
	if err != nil {
		glog.Errorf("directories.Read(%v): %v", dirID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info for %v", dirID)
	}

	return &MapWriteClient{
		MapID:         directory.Map.TreeId,
		twrite:        t.twrite,
		perRPCTimeout: 60 * time.Second,
	}, nil
}

// MapClient returns a verifying MapClient
func (t *Trillian) MapClient(ctx context.Context, dirID string) (trillianMap, error) { // nolint
	directory, err := t.directories.Read(ctx, dirID, false)
	if err != nil {
		glog.Errorf("directories.Read(%v): %v", dirID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info for %v", dirID)
	}

	c, err := tclient.NewMapClientFromTree(t.tmap, directory.Map)
	if err != nil {
		return nil, err
	}
	return &MapClient{
		MapClient:     c,
		perRPCTimeout: 60 * time.Second,
	}, nil
}

// LogClient returns a verifying LogClient.
func (t *Trillian) LogClient(ctx context.Context, dirID string) (trillianLog, error) { // nolint
	directory, err := t.directories.Read(ctx, dirID, false)
	if err != nil {
		glog.Errorf("directories.Read(%v): %v", dirID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info for %v", dirID)
	}

	// Create verifying log client.
	trustedRoot := types.LogRootV1{} // TODO(gbelvin): Store and track trustedRoot.
	return tclient.NewFromTree(t.tlog, directory.Log, trustedRoot)
}

type MapWriteClient struct {
	MapID         int64
	twrite        tpb.TrillianMapWriteClient
	perRPCTimeout time.Duration
}

func (c *MapWriteClient) GetLeavesByRevision(ctx context.Context, rev int64, indexes [][]byte) ([]*tpb.MapLeaf, error) {
	cctx, cancel := context.WithTimeout(ctx, c.perRPCTimeout)
	defer cancel()
	mapLeaves, err := c.twrite.GetLeavesByRevision(cctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    c.MapID,
		Revision: rev,
		Index:    indexes,
	})
	return mapLeaves.GetLeaves(), err
}

func (c *MapWriteClient) WriteLeaves(ctx context.Context, rev int64, leaves []*tpb.MapLeaf) error {
	_, err := c.twrite.WriteLeaves(ctx, &tpb.WriteMapLeavesRequest{
		MapId:          c.MapID,
		Leaves:         leaves,
		ExpectRevision: rev,
	})
	return err
}

// MapClient interacts with the Trillian Map and verifies its responses.
type MapClient struct {
	*tclient.MapClient
	perRPCTimeout time.Duration
}

// GetAndVerifyLatestMapRoot verifies and returns the latest map root.
func (c *MapClient) GetAndVerifyLatestMapRoot(ctx context.Context) (*tpb.SignedMapRoot, *types.MapRootV1, error) {
	cctx, cancel := context.WithTimeout(ctx, c.perRPCTimeout)
	defer cancel()
	rootResp, err := c.Conn.GetSignedMapRoot(cctx, &tpb.GetSignedMapRootRequest{MapId: c.MapID})
	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "GetSignedMapRoot(%v): %v", c.MapID, err)
	}
	mapRoot, err := c.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(%v): %v", c.MapID, err)
	}
	return rootResp.GetMapRoot(), mapRoot, nil
}

// GetAndVerifyMapRootByRevision verifies and returns a specific map root.
func (c *MapClient) GetAndVerifyMapRootByRevision(ctx context.Context,
	rev int64) (*tpb.SignedMapRoot, *types.MapRootV1, error) {
	cctx, cancel := context.WithTimeout(ctx, c.perRPCTimeout)
	defer cancel()
	req := &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    c.MapID,
		Revision: rev,
	}
	resp, err := c.Conn.GetSignedMapRootByRevision(cctx, req)
	if err != nil {
		return nil, nil, status.Errorf(status.Code(err), "GetSignedMapRootByRevision(%v, %v): %v", c.MapID, rev, err)
	}
	rawMapRoot := resp.GetMapRoot()
	mapRoot, err := c.VerifySignedMapRoot(rawMapRoot)
	if err != nil {
		return nil, nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	return rawMapRoot, mapRoot, nil
}

// GetMapLeavesByRevisionNoProof returns the requested map leaves at a specific revision.
// indexes may not contain duplicates.
func (c *MapClient) GetMapLeavesByRevisionNoProof(ctx context.Context, revision int64, indexes [][]byte) ([]*tpb.MapLeaf, error) {
	cctx, cancel := context.WithTimeout(ctx, c.perRPCTimeout)
	defer cancel()
	getResp, err := c.Conn.GetLeavesByRevisionNoProof(cctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    c.MapID,
		Index:    indexes,
		Revision: revision,
	})
	if err != nil {
		s := status.Convert(err)
		return nil, status.Errorf(s.Code(), "GetLeavesByRevisionNoProof(): %v", s.Message())
	}
	return getResp.Leaves, nil
}
