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

package grpcc

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/google/keytransparency/core/client/kt"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/tree/sparse"
	tv "github.com/google/keytransparency/core/tree/sparse/verifier"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/client"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	spb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
	"github.com/google/trillian"
)

const (
	// Each page contains pageSize profiles. Each profile contains multiple
	// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
	// size 16 will contain about 8KB of data.
	pageSize = 16
	// The default capacity used when creating a profiles list in
	// ListHistory.
	defaultListCap = 10
	// TODO: Public keys of trusted monitors.
)

var (
	// ErrRetry occurs when an update request has been submitted, but the
	// results of the udpate are not visible on the server yet. The client
	// must retry until the request is visible.
	ErrRetry = errors.New("update not present on server yet")
	// ErrIncomplete occurs when the server indicates that requested epochs
	// are not available.
	ErrIncomplete = errors.New("incomplete account history")
	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)
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
	cli        spb.KeyTransparencyServiceClient
	vrf        vrf.PublicKey
	kt         *kt.Verifier
	log        client.LogVerifier
	mutator    mutator.Mutator
	RetryCount int
	RetryDelay time.Duration
	trusted    trillian.SignedLogRoot
}

// New creates a new client.
func New(mapID int64,
	client spb.KeyTransparencyServiceClient,
	vrf vrf.PublicKey,
	verifier crypto.PublicKey,
	log client.LogVerifier) *Client {
	return &Client{
		cli:        client,
		vrf:        vrf,
		kt:         kt.New(vrf, tv.New(mapID, sparse.CONIKSHasher), verifier, log),
		log:        log,
		mutator:    entry.New(),
		RetryCount: 1,
		RetryDelay: 3 * time.Second,
	}
}

// GetEntry returns an entry if it exists, and nil if it does not.
func (c *Client) GetEntry(ctx context.Context, userID, appID string, opts ...grpc.CallOption) ([]byte, *trillian.SignedMapRoot, error) {
	e, err := c.cli.GetEntry(ctx, &tpb.GetEntryRequest{
		UserId:        userID,
		AppId:         appID,
		FirstTreeSize: c.trusted.TreeSize,
	}, opts...)
	if err != nil {
		return nil, nil, err
	}

	if err := c.kt.VerifyGetEntryResponse(ctx, userID, appID, &c.trusted, e); err != nil {
		return nil, nil, err
	}

	// Empty case.
	if e.GetCommitted() == nil {
		return nil, e.GetSmr(), nil
	}

	return e.GetCommitted().GetData(), e.GetSmr(), nil
}

func min(x, y int32) int32 {
	if x < y {
		return x
	}
	return y
}

// ListHistory returns a list of profiles starting and ending at given epochs.
// It also filters out all identical consecutive profiles.
// Epochs start at 1.
func (c *Client) ListHistory(ctx context.Context, userID, appID string, start, end int64, opts ...grpc.CallOption) (map[*trillian.SignedMapRoot][]byte, error) {
	if start <= 0 {
		return nil, fmt.Errorf("start=%v, want > 0", start)
	}
	var currentProfile []byte
	profiles := make(map[*trillian.SignedMapRoot][]byte)
	for start <= end {
		resp, err := c.cli.ListEntryHistory(ctx, &tpb.ListEntryHistoryRequest{
			UserId:   userID,
			AppId:    appID,
			Start:    start,
			PageSize: min(int32((end-start)+1), pageSize),
		}, opts...)
		if err != nil {
			return nil, err
		}

		for i, v := range resp.GetValues() {
			Vlog.Printf("Processing entry for %v, epoch %v", userID, start+int64(i))
			err = c.kt.VerifyGetEntryResponse(ctx, userID, appID, &c.trusted, v)
			if err != nil {
				return nil, err
			}

			// Compress profiles that are equal through time.  All
			// nil profiles before the first profile are ignored.
			profile := v.GetCommitted().GetData()
			if bytes.Equal(currentProfile, profile) {
				continue
			}

			// Append the slice and update currentProfile.
			profiles[v.GetSmr()] = profile
			currentProfile = profile
		}
		if resp.NextStart == 0 {
			return nil, ErrIncomplete // No more data.
		}
		start = resp.NextStart // Fetch the next block of results.
	}

	return profiles, nil
}

// Update creates an UpdateEntryRequest for a user, attempt to submit it multiple
// times depending on RetryCount.
func (c *Client) Update(ctx context.Context, userID, appID string, profileData []byte,
	signers []signatures.Signer, authorizedKeys []*tpb.PublicKey,
	opts ...grpc.CallOption) (*tpb.UpdateEntryRequest, error) {
	getResp, err := c.cli.GetEntry(ctx, &tpb.GetEntryRequest{
		UserId:        userID,
		AppId:         appID,
		FirstTreeSize: c.trusted.TreeSize,
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("GetEntry(%v): %v", userID, err)
	}
	Vlog.Printf("Got current entry...")

	if err := c.kt.VerifyGetEntryResponse(ctx, userID, appID, &c.trusted, getResp); err != nil {
		return nil, fmt.Errorf("VerifyGetEntryResponse(): %v", err)
	}

	req, err := c.kt.CreateUpdateEntryRequest(&c.trusted, getResp, c.vrf, userID, appID, profileData, signers, authorizedKeys)
	if err != nil {
		return nil, fmt.Errorf("CreateUpdateEntryRequest: %v", err)
	}

	// Check the mutation before submitting it.
	m, err := proto.Marshal(req.GetEntryUpdate().GetUpdate())
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal(): %v", err)
	}
	if _, err := c.mutator.Mutate(getResp.GetLeafProof().GetLeaf().GetLeafValue(), m); err != nil {
		return nil, fmt.Errorf("Mutate: %v", err)
	}

	err = c.Retry(ctx, req)
	// Retry submitting until an inclusion proof is returned.
	for i := 0; err == ErrRetry && i < c.RetryCount; i++ {
		time.Sleep(c.RetryDelay)
		err = c.Retry(ctx, req)
	}
	return req, err
}

// Retry will take a pre-fabricated request and send it again.
func (c *Client) Retry(ctx context.Context, req *tpb.UpdateEntryRequest) error {
	Vlog.Printf("Sending Update request...")
	updateResp, err := c.cli.UpdateEntry(ctx, req)
	if err != nil {
		return err
	}
	Vlog.Printf("Got current entry...")

	// Validate response.
	if err := c.kt.VerifyGetEntryResponse(ctx, req.UserId, req.AppId, &c.trusted, updateResp.GetProof()); err != nil {
		return fmt.Errorf("VerifyGetEntryResponse(): %v", err)
	}

	// Check if the response is a replay.
	if got, want := updateResp.GetProof().GetLeafProof().Leaf.LeafValue, req.GetEntryUpdate().GetUpdate().GetKeyValue().GetValue(); !bytes.Equal(got, want) {
		return ErrRetry
	}
	return nil
	// TODO: Update previous entry pointer
}
