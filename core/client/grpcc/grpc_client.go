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

// Package grpcc is a client for communicating with the Key Server.  It wraps
// the gRPC apis in a rpc system neutral interface and verifies all responses.
package grpcc

import (
	"bytes"
	"context"
	"crypto"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/google/keytransparency/core/client/kt"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/merkle/hashers"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

const (
	// Each page contains pageSize profiles. Each profile contains multiple
	// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
	// size 16 will contain about 8KB of data.
	pageSize = 16
	// TODO: Public keys of trusted monitors.
)

var (
	// ErrRetry occurs when an update has been queued, but the
	// results of the update differ from the one requested.
	// This indicates that a separate update was in-flight while
	// this update was being submitted. To continue, the client
	// should make a fresh update and try again.
	ErrRetry = errors.New("client: update race condition - try again")
	// ErrWait occurs when an update has been queued, but no change has been
	// observed in the user's account yet.
	ErrWait = errors.New("client: update not present yet - wait some more")
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
	cli        pb.KeyTransparencyClient
	domainID   string
	kt         *kt.Verifier
	mutator    mutator.Func
	RetryCount int
	RetryDelay time.Duration
	trusted    trillian.SignedLogRoot
}

// NewFromConfig creates a new client from a config
func NewFromConfig(ktClient pb.KeyTransparencyClient, config *pb.Domain) (*Client, error) {
	// Log Hasher.
	logHasher, err := hashers.NewLogHasher(config.GetLog().GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("Failed creating LogHasher: %v", err)
	}

	// Log Key
	logPubKey, err := der.UnmarshalPublicKey(config.GetLog().GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("Failed parsing Log public key: %v", err)
	}

	// Map Hasher
	mapHasher, err := hashers.NewMapHasher(config.GetMap().GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("Failed creating MapHasher: %v", err)
	}

	// Map Key
	mapPubKey, err := der.UnmarshalPublicKey(config.GetMap().GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("Failed parsing Map public key: %v", err)
	}

	// VRF key
	vrfPubKey, err := p256.NewVRFVerifierFromRawKey(config.GetVrf().GetDer())
	if err != nil {
		return nil, fmt.Errorf("Error parsing vrf public key: %v", err)
	}

	// TODO(gbelvin): set retry delay.
	logVerifier := client.NewLogVerifier(logHasher, logPubKey)
	return New(ktClient, config.DomainId, vrfPubKey, mapPubKey, mapHasher, logVerifier), nil
}

// New creates a new client.
func New(ktClient pb.KeyTransparencyClient,
	domainID string,
	vrf vrf.PublicKey,
	mapPubKey crypto.PublicKey,
	mapHasher hashers.MapHasher,
	logVerifier client.LogVerifier) *Client {
	return &Client{
		cli:        ktClient,
		domainID:   domainID,
		kt:         kt.New(vrf, mapHasher, mapPubKey, logVerifier),
		mutator:    entry.New(),
		RetryCount: 1,
		RetryDelay: 3 * time.Second,
	}
}

// GetEntry returns an entry if it exists, and nil if it does not.
func (c *Client) GetEntry(ctx context.Context, userID, appID string, opts ...grpc.CallOption) ([]byte, *trillian.SignedMapRoot, error) {
	e, err := c.VerifiedGetEntry(ctx, appID, userID)
	if err != nil {
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
func (c *Client) ListHistory(ctx context.Context, userID, appID string, start, end int64, opts ...grpc.CallOption) (map[*trillian.SignedMapRoot][]byte, error) {
	if start < 0 {
		return nil, fmt.Errorf("start=%v, want >= 0", start)
	}
	var currentProfile []byte
	profiles := make(map[*trillian.SignedMapRoot][]byte)
	epochsReceived := int64(0)
	epochsWant := end - start + 1
	for epochsReceived < epochsWant {
		resp, err := c.cli.ListEntryHistory(ctx, &pb.ListEntryHistoryRequest{
			DomainId: c.domainID,
			UserId:   userID,
			AppId:    appID,
			Start:    start,
			PageSize: min(int32((end-start)+1), pageSize),
		}, opts...)
		if err != nil {
			return nil, err
		}
		epochsReceived += int64(len(resp.GetValues()))

		for i, v := range resp.GetValues() {
			Vlog.Printf("Processing entry for %v, epoch %v", userID, start+int64(i))
			err = c.kt.VerifyGetEntryResponse(ctx, c.domainID, appID, userID, &c.trusted, v)
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
			break // No more data.
		}
		start = resp.NextStart // Fetch the next block of results.
	}

	if epochsReceived < epochsWant {
		return nil, ErrIncomplete
	}

	return profiles, nil
}

// Update creates an UpdateEntryRequest for a user,
// attempt to submit it multiple times depending on RetryCount.
func (c *Client) Update(ctx context.Context, u *tpb.User, signers []signatures.Signer) (*entry.Mutation, error) {
	if got, want := u.DomainId, c.domainID; got != want {
		return nil, fmt.Errorf("u.DomainID: %v, want %v", got, want)
	}
	// 1. pb.User + ExistingEntry -> Mutation
	m, err := c.newMutation(ctx, u)
	if err != nil {
		return nil, err
	}

	if err := c.QueueMutation(ctx, m, signers); err != nil {
		return nil, err
	}

	// 3. Wait for update
	m, err = c.WaitForUserUpdate(ctx, m)
	for i := 0; i < c.RetryCount; i++ {
		switch err {
		case ErrWait:
			// Try again.
		case ErrRetry:
			if err := c.QueueMutation(ctx, m, signers); err != nil {
				return nil, err
			}
		default:
			return m, err
		}
		m, err = c.WaitForUserUpdate(ctx, m)
	}
	return m, err
}

// QueueMutation signs m and sends it to the server.
func (c *Client) QueueMutation(ctx context.Context, m *entry.Mutation, signers []signatures.Signer) error {
	req, err := m.SerializeAndSign(signers, c.trusted.GetTreeSize())
	if err != nil {
		return fmt.Errorf("SerializeAndSign(): %v", err)
	}

	Vlog.Printf("Sending Update request...")
	// 2. Queue Mutation
	_, err = c.cli.UpdateEntry(ctx, req)
	return err
}

// newMutation fetches the current index and value for a user and prepares a mutation.
func (c *Client) newMutation(ctx context.Context, u *tpb.User) (*entry.Mutation, error) {
	e, err := c.VerifiedGetEntry(ctx, u.AppId, u.UserId)
	if err != nil {
		return nil, err
	}
	oldLeaf := e.GetLeafProof().GetLeaf().GetLeafValue()
	Vlog.Printf("Got current entry...")

	index, err := c.kt.Index(e.GetVrfProof(), u.DomainId, u.AppId, u.UserId)
	if err != nil {
		return nil, err
	}

	mutation := entry.NewMutation(index, u.DomainId, u.AppId, u.UserId)

	if err := mutation.SetPrevious(oldLeaf, true); err != nil {
		return nil, err
	}

	if err := mutation.SetCommitment(u.PublicKeyData); err != nil {
		return nil, err
	}

	if len(u.AuthorizedKeys) != 0 {
		if err := mutation.ReplaceAuthorizedKeys(u.AuthorizedKeys); err != nil {
			return nil, err
		}
	}

	return mutation, nil
}

// WaitForUserUpdate waits for the STH to be updated, indicating the next epoch has been created,
// it then queries the current value for the user and checks it against the requested mutation.
// If the current value has not changed, WaitForUpdate returns ErrWaitSomeMore.
// If the current value has changed, but does not match the requested mutation,
// WaitForUpdate returns a new mutation, built with the current value and ErrRetry.
// If the current value matches the request, no mutation and no error are returned.
func (c *Client) WaitForUserUpdate(ctx context.Context, m *entry.Mutation) (*entry.Mutation, error) {
	sth := &c.trusted
	// Wait for STH to change.
	if err := c.WaitForSTHUpdate(ctx, sth); err != nil {
		return nil, err
	}

	// GetEntry.
	e, err := c.VerifiedGetEntry(ctx, m.AppID, m.UserID)
	if err != nil {
		return nil, err
	}
	Vlog.Printf("Got current entry...")

	// Verify.
	cntLeaf := e.GetLeafProof().GetLeaf().GetLeafValue()
	cntValue, err := entry.FromLeafValue(cntLeaf)
	if err != nil {
		return nil, err
	}
	switch {
	case m.EqualsRequested(cntValue):
		return nil, nil
	case m.EqualsPrevious(cntValue):
		return m, ErrWait
	default:
		// Race condition: some change got in first.
		// Value has changed, but it's not what we asked for.
		// Retry based on new cnt value.

		// To break the tie between two devices that are fighting
		// each other, this error should be propogated back to the user.
		copyPreviousLeafData := false
		if err := m.SetPrevious(cntLeaf, copyPreviousLeafData); err != nil {
			return nil, fmt.Errorf("waitforupdate: SetPrevious(): %v", err)
		}
		return m, errors.New("client: update race condition - try again")
	}
}

// WaitForSTHUpdate blocks until the log root reported by the server has moved
// beyond sth or times out.
func (c *Client) WaitForSTHUpdate(ctx context.Context, sth *trillian.SignedLogRoot) error {
	b := &backoff.Backoff{
		Min:    100 * time.Millisecond,
		Max:    10 * time.Second,
		Factor: 1.2,
		Jitter: true,
	}

	for {
		select {
		case <-time.After(b.Duration()):
			resp, err := c.cli.GetLatestEpoch(ctx, &pb.GetLatestEpochRequest{
				DomainId:      c.domainID,
				FirstTreeSize: sth.TreeSize,
			})
			if err != nil {
				return err
			}
			if resp.GetLogRoot().TreeSize <= sth.TreeSize {
				// The LogRoot is not updated yet.
				// Wait some more.
				continue
			}
			return nil // We're done!

		case <-ctx.Done():
			return status.Errorf(codes.DeadlineExceeded,
				"Timed out waiting for sth update: %v", ctx.Err())
		}
	}
}
