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
	"runtime"
	"sync"

	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"

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

	_, spanEnd := monitoring.StartSpan(ctx, "BatchVerifyGetUserIndex.Verify")
	defer spanEnd()

	// Proof producer
	type proof struct {
		userID string
		proof  []byte
	}
	proofs := make(chan proof)
	done := make(chan struct{})
	defer close(done)
	go func() {
		defer close(proofs)
		for UID, p := range resp.GetProofs() {
			select {
			case proofs <- proof{userID: UID, proof: p}:
			case <-done:
				return
			}
		}
	}()

	// Proof verifier
	type result struct {
		userID string
		index  []byte
		err    error
	}
	results := make(chan result)
	var wg sync.WaitGroup
	for w := 0; w < runtime.NumCPU(); w++ {
		wg.Add(1)
		// Proof verifier worker
		go func() {
			defer wg.Done()
			for p := range proofs {
				index, err := c.Index(p.proof, c.DirectoryID, p.userID)
				select {
				case results <- result{userID: p.userID, index: index, err: err}:
				case <-done:
					return
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	// Result consumer
	indexByUser := make(map[string][]byte)
	for r := range results {
		if r.err != nil {
			return nil, r.err // Done will be closed by deferred call.
		}
		indexByUser[r.userID] = r.index
	}
	return indexByUser, nil
}

// BatchVerifiedGetUser returns verified leaf values by userID.
// Returns the MapRoot (revision) at which the values were fetched. This could be any MapRoot.
// TODO(gbelvin): Verify that the returned map root is indeed the latest map root.
func (c *Client) BatchVerifiedGetUser(ctx context.Context, userIDs []string) (
	*types.MapRootV1, map[string]*pb.MapLeaf, error) {
	logReq := c.LastVerifiedLogRoot()
	resp, err := c.cli.BatchGetUser(ctx, &pb.BatchGetUserRequest{
		DirectoryId:  c.DirectoryID,
		UserIds:      userIDs,
		LastVerified: logReq,
	})
	if err != nil {
		return nil, nil, err
	}

	lr, err := c.VerifyLogRoot(logReq, resp.Revision.GetLatestLogRoot())
	if err != nil {
		return nil, nil, err
	}
	smr, err := c.VerifyMapRevision(lr, resp.Revision.GetMapRoot())
	if err != nil {
		return nil, nil, err
	}

	leavesByUserID := make(map[string]*pb.MapLeaf)
	for userID, leaf := range resp.MapLeavesByUserId {
		if err := c.VerifyMapLeaf(c.DirectoryID, userID, leaf, smr); err != nil {
			return nil, nil, err
		}
		leavesByUserID[userID] = leaf
	}
	return smr, leavesByUserID, nil
}
