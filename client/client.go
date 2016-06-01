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
	"bytes"
	"errors"
	"log"
	"time"

	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse/memtree"
	"github.com/google/e2e-key-server/vrf"

	logclient "github.com/google/certificate-transparency/go/client"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

const (
	retryDelay = 3 * time.Second
	// TODO: Public key of signer.
	// TODO: Public keys of trusted monitors.
	// TODO: Domain to API URL resolution.
)

var (
	errFailedVerification = errors.New("Server response failed verification")
	errFailedSubmit       = errors.New("Failed submission")
	ErrRetry              = errors.New("Update not present on server yet")
)

// Client is a helper library for issuing updates to the key server.
// Client Responsibilities
// - Trust Model:
// - - Trusted Monitors
// - - Verify last X days
// - Gossip - What is the current value of the root?
// -  - Gossip advancement: advance state between current and server.
// - Sender queries - Do queries match up against the gossip root?
// - - List trusted monitors.
// - Key Owner
// - - Periodically query own keys. Do they match the private keys I have?
// - - Sign key update requests.
type Client struct {
	cli        v2pb.E2EKeyServiceClient
	vrf        vrf.PublicKey
	RetryCount int
	factory    tree.SparseFactory
	ctlog      *logclient.LogClient
}

// New creates a new client.
func New(client v2pb.E2EKeyServiceClient, vrf vrf.PublicKey, mapLogURL string) *Client {
	return &Client{
		cli:        client,
		vrf:        vrf,
		RetryCount: 1,
		factory:    memtree.NewFactory(),
		ctlog:      logclient.New(mapLogURL),
	}
}

// GetEntry returns an entry if it exists, and nil if it does not.
func (c *Client) GetEntry(ctx context.Context, userID string, opts ...grpc.CallOption) (*pb.Profile, error) {
	// Error, ctx is not being passed
	e, err := c.cli.GetEntry(ctx, &pb.GetEntryRequest{
		UserId: userID,
	}, opts...)
	if err != nil {
		return nil, err
	}

	if !c.verifyGetEntryResponse(userID, e) {
		return nil, errFailedVerification
	}

	if !c.verifyLog(e.GetSeh()) {
		return nil, errFailedVerification
	}

	// Empty case.
	if e.Profile == nil {
		return nil, nil
	}

	profile := new(pb.Profile)
	if err := proto.Unmarshal(e.Profile, profile); err != nil {
		log.Printf("Error unmarshaling profile: %v", err)
		return nil, err
	}
	return profile, nil
}

// Update creates an UpdateEntryRequest for a user.
func (c *Client) Update(ctx context.Context, userID string, profile *pb.Profile, opts ...grpc.CallOption) (*pb.UpdateEntryRequest, error) {
	getResp, err := c.cli.GetEntry(ctx, &pb.GetEntryRequest{UserId: userID}, opts...)
	if err != nil {
		return nil, err
	}

	if !c.verifyGetEntryResponse(userID, getResp) {
		return nil, errFailedVerification
	}

	// Extract index from a prior GetEntry call.
	index := c.vrf.Index(getResp.Vrf)
	prevEntry := new(pb.Entry)
	if err := proto.Unmarshal(getResp.GetLeafProof().LeafData, prevEntry); err != nil {
		log.Printf("Error unmarshaling Entry from leaf proof: %v", err)
		return nil, err
	}

	// Commit to profile.
	profileData, err := proto.Marshal(profile)
	if err != nil {
		log.Printf("Unexpected profile marshalling error: %v", err)
		return nil, err
	}
	key, commitment, err := commitments.CommitName(userID, profileData)
	if err != nil {
		return nil, err
	}

	// Create new Entry.
	entry := &pb.Entry{
		Commitment:     commitment,
		AuthorizedKeys: prevEntry.AuthorizedKeys,
		UpdateCount:    prevEntry.UpdateCount + 1,
	}

	// Sign Entry.
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, err
	}
	kv := &pb.KeyValue{
		Key:   index[:],
		Value: entryData,
	}
	kvData, err := proto.Marshal(kv)
	if err != nil {
		return nil, err
	}
	signedkv := &pb.SignedKV{
		KeyValue:   kvData,
		Signatures: nil, // TODO: Apply Signatures.
		// TODO: include hash of previous entry.
	}

	// Send request.
	req := &pb.UpdateEntryRequest{
		UserId: userID,
		EntryUpdate: &pb.EntryUpdate{
			Update:        signedkv,
			Profile:       profileData,
			CommitmentKey: key,
		},
	}

	err = c.Retry(ctx, req)
	// Retry submitting until an incluion proof is returned.
	for i := 0; err == ErrRetry && i < c.RetryCount; i++ {
		time.Sleep(retryDelay)
		err = c.Retry(ctx, req)
	}
	return req, err
}

func (c *Client) Retry(ctx context.Context, req *pb.UpdateEntryRequest) error {
	updateResp, err := c.cli.UpdateEntry(ctx, req)
	if err != nil {
		return err
	}
	// Validate response.
	if !c.verifyGetEntryResponse(req.UserId, updateResp.GetProof()) {
		return errFailedVerification
	}

	keyvalue := new(pb.KeyValue)
	if err := proto.Unmarshal(req.GetEntryUpdate().GetUpdate().KeyValue, keyvalue); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return err
	}

	if got := updateResp.GetProof().GetLeafProof().LeafData; bytes.Equal(got, keyvalue.Value) {
		log.Printf("Retry(%v) Matched", req.UserId)
		return nil
	} else {
		log.Printf("Retry(%v) returned: %v, want %v", req.UserId, got, req.GetEntryUpdate().Profile)
		return ErrRetry
	}
	// TODO: Update previous entry pointer
}
