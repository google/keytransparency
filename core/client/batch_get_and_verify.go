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
		DirectoryId: c.directoryID,
		UserIds:     userIDs,
	})
	if err != nil {
		return nil, err
	}

	indexByUser := make(map[string][]byte)
	for userID, proof := range resp.Proofs {
		index, err := c.Index(proof, c.directoryID, userID)
		if err != nil {
			return nil, err
		}
		indexByUser[userID] = index
	}
	return indexByUser, nil
}
