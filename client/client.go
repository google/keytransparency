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

// Client for communicating with the Key server.

package client

import (
	"crypto/hmac"

	"github.com/gdbelvin/e2e-key-server/db/commitments"
	"github.com/gdbelvin/e2e-key-server/tree"
	"github.com/gdbelvin/e2e-key-server/tree/sparse/memtree"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
	pb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys"
	v2pb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys_v2"
)

// Client is a helper library for issuing updates to the key server.
type Client struct {
	v2pb.E2EKeyServiceClient
	factory tree.SparseFactory
}

// New creates a new client.
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
	// TODO: formally define and fix.
	index := previous.Index

	// Construct Entry.
	key, commitment, err := commitments.CommitName(userID, profileData)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error generating profile commitment: %v", err)
	}
	entry := &ctmap.Entry{
		// TODO: Pull entry key from previous entry.
		// TODO: Increment update count from previous entry.
		ProfileCommitment: commitment,
		Index:             index,
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

// VerifyMerkleTreeProof returns nil if the merkle tree neighbors list is valid
// and the provided signed epoch head has a valid signature.
func (c *Client) VerifyMerkleTreeProof(neighbors [][]byte, expectedRoot []byte, index []byte, entry []byte) error {
	// TODO: replace with static merkle tree
	m := c.factory.FromNeighbors(neighbors, index, entry)

	// Get calculated root value.
	calculatedRoot, _ := m.ReadRoot(nil)

	// Verify the built tree root is as expected.
	if ok := hmac.Equal(expectedRoot, calculatedRoot); !ok {
		return grpc.Errorf(codes.InvalidArgument, "Merkle Verification Failed. Root=%v, want %v", calculatedRoot, expectedRoot)
	}

	return nil
}
