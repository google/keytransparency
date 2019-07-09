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
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()
	req := &pb.GetUserRequest{
		DirectoryId:          c.DirectoryID,
		UserId:               userID,
		LastVerifiedTreeSize: int64(c.trusted.TreeSize),
	}
	resp, err := c.cli.GetUser(ctx, req)
	if err != nil {
		return nil, nil, err
	}

	if err := c.VerifyGetUser(c.trusted, req, resp); err != nil {
		return nil, nil, err
	}

	// TODO(gbelvin): Refactor updating the SLR into a separate tracker package.
	slr, smr, err := c.VerifyRevision(resp.Revision, c.trusted)
	if err != nil {
		return nil, nil, err
	}
	c.updateTrusted(slr)

	return smr, resp.Leaf, nil
}

// VerifiedGetLatestRevision fetches the latest revision from the key server.
// It also verifies the consistency from the last seen revision.
// Returns the latest log root and the latest map root.
func (c *Client) VerifiedGetLatestRevision(ctx context.Context) (*types.LogRootV1, *types.MapRootV1, error) {
	// Only one method should attempt to update the trusted root at time.
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()

	e, err := c.cli.GetLatestRevision(ctx, &pb.GetLatestRevisionRequest{
		DirectoryId:          c.DirectoryID,
		LastVerifiedTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, nil, err
	}

	slr, smr, err := c.VerifyRevision(e, c.trusted)
	if err != nil {
		return nil, nil, err
	}
	// At this point, the SignedLogRoot has been verified as consistent.
	c.updateTrusted(slr)

	// Also check that the map revision returned is the latest one.
	// TreeSize - 1 == mapRoot.Revision.
	wantRevision, err := mapRevisionFor(slr)
	if err != nil {
		return nil, nil, err
	}
	if smr.Revision != wantRevision {
		return nil, nil, fmt.Errorf("map revision is not the most recent. smr.Revison: %v != slr.TreeSize-1: %v", smr.Revision, slr.TreeSize-1)
	}
	return slr, smr, nil
}

// VerifiedGetRevision fetches the requested revision from the key server.
// It also verifies the consistency of the latest log root against the last seen log root.
// Returns the latest log root and the requested map root.
func (c *Client) VerifiedGetRevision(ctx context.Context, revision int64) (*types.LogRootV1, *types.MapRootV1, error) {
	// Only one method should attempt to update the trusted root at time.
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()

	e, err := c.cli.GetRevision(ctx, &pb.GetRevisionRequest{
		DirectoryId:          c.DirectoryID,
		Revision:             revision,
		LastVerifiedTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, nil, err
	}

	slr, smr, err := c.VerifyRevision(e, c.trusted)
	if err != nil {
		return nil, nil, err
	}

	c.updateTrusted(slr)
	return slr, smr, nil
}

// VerifiedListHistory performs one list history operation, verifies and returns the results.
func (c *Client) VerifiedListHistory(ctx context.Context, userID string, start int64, count int32) (
	map[*types.MapRootV1][]byte, int64, error) {
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()
	resp, err := c.cli.ListEntryHistory(ctx, &pb.ListEntryHistoryRequest{
		DirectoryId:          c.DirectoryID,
		UserId:               userID,
		LastVerifiedTreeSize: int64(c.trusted.TreeSize),
		Start:                start,
		PageSize:             count,
	})
	if err != nil {
		return nil, 0, err
	}

	// The roots are only updated once per API call.
	// TODO(gbelvin): Remove the redundancy inside the responses.
	var slr *types.LogRootV1
	var smr *types.MapRootV1
	profiles := make(map[*types.MapRootV1][]byte)
	for _, v := range resp.GetValues() {
		slr, smr, err = c.VerifyRevision(v.Revision, c.trusted)
		if err != nil {
			return nil, 0, err
		}
		if err = c.VerifyMapLeaf(c.DirectoryID, userID, v.Leaf, smr); err != nil {
			return nil, 0, err
		}
		Vlog.Printf("Processing entry for %v, revision %v", userID, smr.Revision)
		glog.V(2).Infof("Processing entry for %v, revision %v", userID, smr.Revision)
		profiles[smr] = v.GetLeaf().GetCommitted().GetData()
	}
	if slr != nil {
		c.updateTrusted(slr)
	}
	return profiles, resp.NextStart, nil
}
