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

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// BatchVerifyGetUserIndex fetches and verifies the indexes for a list of users.
func (c *Client) BatchVerifyGetUserIndex(ctx context.Context, userIDs []string) (map[string][]byte, error) {
	resp, err := c.cli.BatchGetUserIndex(ctx, &pb.BatchGetUserIndexRequest{
		DirectoryId: c.DirectoryID,
		UserIds:     userIDs,
	})
	if err != nil {
		return nil, err
	}

	indexByUser := make(map[string][]byte)
	for userID, proof := range resp.Proofs {
		index, err := c.Index(proof, c.DirectoryID, userID)
		if err != nil {
			return nil, err
		}
		indexByUser[userID] = index
	}
	return indexByUser, nil
}

// BatchVerifiedGetUser returns verified leaf values by userID.
func (c *Client) BatchVerifiedGetUser(ctx context.Context, userIDs []string) (map[string]*pb.MapLeaf, error) {
	c.trustedLock.Lock()
	defer c.trustedLock.Unlock()
	resp, err := c.cli.BatchGetUser(ctx, &pb.BatchGetUserRequest{
		DirectoryId:          c.DirectoryID,
		UserIds:              userIDs,
		LastVerifiedTreeSize: int64(c.trusted.TreeSize),
	})
	if err != nil {
		return nil, err
	}

	slr, smr, err := c.VerifyRevision(resp.Revision, c.trusted)
	if err != nil {
		return nil, err
	}
	c.updateTrusted(slr)

	leavesByUserID := make(map[string]*pb.MapLeaf)
	for userID, leaf := range resp.MapLeavesByUserId {
		if err := c.VerifyMapLeaf(c.DirectoryID, userID, leaf, smr); err != nil {
			return nil, err
		}
		leavesByUserID[userID] = leaf
	}
	return leavesByUserID, nil
}
