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
	"crypto/rand"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"github.com/google/e2e-key-server/common"

	v2pb "github.com/google/e2e-key-server/proto/v2"
)

const (
	// nonceBytes is the number of bytes to use as the nonce in the profile
	// commitment.
	nonceBytes = 16
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

	// Generate nonce.
	nonce := make([]byte, nonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error generating nonce: %v", err)
	}

	// Get Index
	// TODO: formally define and fix.
	index := previous.IndexSignature

	// Construct Entry.
	commitment, err := common.GenerateProfileCommitment(nonce, profileData)
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
		Entry: entryData,
	}

	return &v2pb.UpdateEntryRequest{
		UserId: userID,
		SignedEntryUpdate: signedEntryUpdate,
		Profile:           profileData,
		ProfileNonce: nonce,
	}, nil
}

// VerifyMerkleTreeProof returns nil if the merkle tree neighbors list is valid
// and the provided signed epoch head has a valid signature.
func (c *Client) VerifyMerkleTreeProof(neighbors [][]byte, signedHeads []*v2pb.SignedEpochHead, index []byte, entry *v2pb.Entry) error {
	// Calculate the leaf hashed value. Depth is the length of the neighbors
	// list.
	leafValue, err := CalculateLeafValue(len(neighbors), index, entry)
	if err != nil {
		return err
	}

	// TODO(cesarghali): verify SEH signatures.

	// Pick one of the provided signed epoch heads.
	// TODO(cesarghali): better pick based on key ID.
	seh := signedHeads[0]
	headValue, err := common.GetHeadValue(seh)
	if err != nil {
		return err
	}

	// Verify the tree neighbors.
	if err := common.VerifyMerkleTreeNeighbors(neighbors, headValue, index, leafValue); err != nil {
		return err
	}
	return nil
}

// CalculateLeafValue calculate the value of a leaf node based on entry.
func CalculateLeafValue(depth int, index []byte, entry *v2pb.Entry) ([]byte, error) {
	// Marshal entry.
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Unexpected entry marshalling error: %v", err)
	}

	// Rebuild the signedEntry update given entry. Client should regenerate
	// the signatures.
	signedEntryUpdate := &v2pb.SignedEntryUpdate{
		// TODO(cesarghali): need to add signatures.
		Entry: entryData,
	}
	signedEntryUpdateData, err := proto.Marshal(signedEntryUpdate)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Unexpected signed entry update marshalling error: %v", err)
	}

	// Calculate the SignedEntryUpdate hash.
	dataHash := common.Hash(signedEntryUpdateData)
	return common.HashLeaf(common.LeafIdentifier, depth, index, dataHash), nil
}
