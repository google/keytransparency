// Copyright 2015 Google Inc. All Rights Reserved.
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

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/common"
	"github.com/google/e2e-key-server/merkle"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Client is a helper library for issuing updates to the key server.
type Client struct {
	v2pb.E2EKeyServiceClient
}

// New creates a new client.
func New(client v2pb.E2EKeyServiceClient) *Client {
	return &Client{client}
}

func (c *Client) Update(profile *v2pb.Profile, userID string) (*v2pb.UpdateEntryRequest, error) {
	ctx := context.Background()
	req := &v2pb.GetEntryRequest{UserId: userID}
	resp, err := c.GetEntry(ctx, req)
	if err != nil {
		return nil, grpc.Errorf(codes.Unavailable, "Unable to query server %v", err)
	}

	return CreateUpdate(profile, userID, resp)
}

func CreateUpdate(profile *v2pb.Profile, userID string, previous *v2pb.GetEntryResponse) (*v2pb.UpdateEntryRequest, error) {

	// Construct Profile.
	profileData, err := proto.Marshal(profile)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Unexpected profile marshalling error: %v", err)
	}

	// Get Index
	// TODO: formally define and fix.
	index := previous.Index

	// Construct Entry.
	commitmentKey, commitment, err := common.Commitment(profileData)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error generating profile commitment: %v", err)
	}
	entry := &v2pb.Entry{
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
	signedEntryUpdate := &v2pb.SignedEntryUpdate{
		// TODO: Apply Signatures.
		NewEntry: entryData,
	}

	return &v2pb.UpdateEntryRequest{
		UserId:            userID,
		SignedEntryUpdate: signedEntryUpdate,
		Profile:           profileData,
		CommitmentKey:     commitmentKey,
	}, nil
}

// VerifyMerkleTreeProof returns nil if the merkle tree neighbors list is valid
// and the provided signed epoch head has a valid signature.
func (c *Client) VerifyMerkleTreeProof(neighbors [][]byte, expectedRoot []byte, index []byte, entry []byte) error {
	m, err := merkle.FromNeighbors(neighbors, index, entry)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Unexpected building expected tree error: %v", err)
	}

	// Get calculated root value.
	calculatedRoot, err := m.Root(0)
	if err != nil {
		return err
	}

	// Verify the built tree root is as expected.
	if got, want := hmac.Equal(expectedRoot, calculatedRoot), true; got != want {
		return grpc.Errorf(codes.InvalidArgument, "Invalid merkle tree neighbors list")
	}

	return nil
}
