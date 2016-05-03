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

// Client for communicating with the Key Server.
// Implements verification and convenience functions.

package client

import (
	"crypto/hmac"
	"crypto/sha256"

	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse/memtree"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

// Client forms and validates requests and responses to the Key Server.
type Client struct {
	v2pb.E2EKeyServiceClient
	factory tree.SparseFactory
}

// New wraps a raw GRPC E2EKeyServiceClient with verification logic.
func New(client v2pb.E2EKeyServiceClient) *Client {
	return &Client{client, memtree.NewFactory()}
}

// Update creates an UpdateEntryRequest for a user.
func (c *Client) Update(profile *pb.Profile, userID string) (*pb.UpdateEntryRequest, error) {
	ctx := context.Background()
	req := &pb.GetEntryRequest{UserId: userID}
	resp, err := c.GetEntry(ctx, req)
	if err != nil {
		return nil, grpc.Errorf(codes.Unavailable, "Unable to query server %v", err)
	}

	return CreateUpdate(profile, userID, resp)
}

func CreateUpdate(profile *pb.Profile, userID string, previous *pb.GetEntryResponse) (*pb.UpdateEntryRequest, error) {

	// Construct Profile.
	profileData, err := proto.Marshal(profile)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Unexpected profile marshalling error: %v", err)
	}

	// Get Index
	vrf := previous.Vrf
	index := sha256.Sum256(vrf)

	// Construct Entry.
	key, commitment, err := commitments.CommitName(userID, profileData)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error generating profile commitment: %v", err)
	}
	entry := &ctmap.Entry{
		// TODO: Pull entry key from previous entry.
		// TODO: Increment update count from previous entry.
		ProfileCommitment: commitment,
		Index:             index[:],
	}

	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Unexpected entry marshalling error: %v", err)
	}

	// Construct SignedEntryUpdate.
	signedEntryUpdate := &ctmap.SignedEntryUpdate{
		// TODO: Apply Signatures.
		NewEntry: entryData,
	}

	return &pb.UpdateEntryRequest{
		UserId:            userID,
		SignedEntryUpdate: signedEntryUpdate,
		Profile:           profileData,
		CommitmentKey:     key,
	}, nil
}

// VerifyMerkleTreeProof returns true if the neighbor hashes and entry chain up to the expectedRoot.
func (c *Client) VerifyMerkleTreeProof(neighbors [][]byte, expectedRoot []byte, index []byte, entry []byte) bool {
	// TODO: replace with static merkle tree
	m := c.factory.FromNeighbors(neighbors, index, entry)
	calculatedRoot, _ := m.ReadRoot(nil)
	return hmac.Equal(expectedRoot, calculatedRoot)
}
