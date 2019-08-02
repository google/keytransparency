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

package client

import (
	"context"
	"fmt"

	"github.com/golang/glog"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// VerifiedGetUser fetches and verifies the results of GetUser.
func (c *Client) VerifiedGetUser(ctx context.Context, userID string) (*types.MapRootV1, *pb.MapLeaf, error) {
	logReq := c.LastVerifiedLogRoot()
	req := &pb.GetUserRequest{
		DirectoryId:  c.DirectoryID,
		UserId:       userID,
		LastVerified: logReq,
	}
	resp, err := c.cli.GetUser(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	lr, err := c.VerifyLogRoot(logReq, resp.Revision.GetLatestLogRoot())
	if err != nil {
		return nil, nil, err
	}
	mr, err := c.VerifyMapRevision(lr, resp.Revision.GetMapRoot())
	if err != nil {
		return nil, nil, err
	}
	if err := c.VerifyMapLeaf(c.DirectoryID, userID, resp.Leaf, mr); err != nil {
		return nil, nil, err
	}

	return mr, resp.Leaf, nil
}

// VerifiedGetLatestRevision fetches the latest revision from the key server.
// It also verifies the consistency from the last seen revision.
// Returns the latest log root and the latest map root.
func (c *Client) VerifiedGetLatestRevision(ctx context.Context) (*types.LogRootV1, *types.MapRootV1, error) {
	logReq := c.LastVerifiedLogRoot()
	resp, err := c.cli.GetLatestRevision(ctx, &pb.GetLatestRevisionRequest{
		DirectoryId:  c.DirectoryID,
		LastVerified: logReq,
	})
	if err != nil {
		return nil, nil, err
	}

	lr, err := c.VerifyLogRoot(logReq, resp.GetLatestLogRoot())
	if err != nil {
		return nil, nil, err
	}
	mr, err := c.VerifyMapRevision(lr, resp.GetMapRoot())
	if err != nil {
		return nil, nil, err
	}

	// Also check that the map revision returned is the latest one.
	// TreeSize - 1 == mapRoot.Revision.
	wantRevision, err := mapRevisionFor(lr)
	if err != nil {
		return nil, nil, err
	}
	if mr.Revision != wantRevision {
		return nil, nil, fmt.Errorf("map revision is not the most recent. smr.Revison: %v != slr.TreeSize-1: %v", mr.Revision, lr.TreeSize-1)
	}
	return lr, mr, nil
}

// VerifiedGetRevision fetches the requested revision from the key server.
// It also verifies the consistency of the latest log root against the last seen log root.
// Returns the requested map root.
func (c *Client) VerifiedGetRevision(ctx context.Context, revision int64) (*types.MapRootV1, error) {
	logReq := c.LastVerifiedLogRoot()
	req := &pb.GetRevisionRequest{
		DirectoryId:  c.DirectoryID,
		Revision:     revision,
		LastVerified: logReq,
	}
	resp, err := c.cli.GetRevision(ctx, req)
	if err != nil {
		return nil, err
	}

	lr, err := c.VerifyLogRoot(logReq, resp.GetLatestLogRoot())
	if err != nil {
		return nil, err
	}
	mr, err := c.VerifyMapRevision(lr, resp.GetMapRoot())
	if err != nil {
		return nil, err
	}

	return mr, nil
}

// VerifiedListHistory performs one list history operation, verifies and returns the results.
func (c *Client) VerifiedListHistory(ctx context.Context, userID string, start int64, count int32) (
	map[*types.MapRootV1][]byte, int64, error) {
	logReq := c.LastVerifiedLogRoot()
	resp, err := c.cli.ListEntryHistory(ctx, &pb.ListEntryHistoryRequest{
		DirectoryId:  c.DirectoryID,
		UserId:       userID,
		LastVerified: logReq,
		Start:        start,
		PageSize:     count,
	})
	if err != nil {
		return nil, 0, err
	}

	// The roots are only updated once per API call.
	// TODO(gbelvin): Remove the redundancy inside the responses.
	var lr *types.LogRootV1
	profiles := make(map[*types.MapRootV1][]byte)
	for _, v := range resp.GetValues() {
		if lr == nil {
			lr, err = c.VerifyLogRoot(logReq, v.GetRevision().GetLatestLogRoot())
			if err != nil {
				return nil, 0, err
			}
		}
		mr, err := c.VerifyMapRevision(lr, v.GetRevision().GetMapRoot())
		if err != nil {
			return nil, 0, err
		}
		if err := c.VerifyMapLeaf(c.DirectoryID, userID, v.Leaf, mr); err != nil {
			return nil, 0, err
		}
		Vlog.Printf("Processing entry for %v, revision %v", userID, mr.Revision)
		glog.V(2).Infof("Processing entry for %v, revision %v", userID, mr.Revision)
		profiles[mr] = v.GetLeaf().GetCommitted().GetData()
	}
	return profiles, resp.NextStart, nil
}
