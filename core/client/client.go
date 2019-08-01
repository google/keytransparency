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

// Package client is a client for communicating with the Key Server.
// It wraps the gRPC APIs and verifies all responses.
package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"sort"
	"time"

	"github.com/google/keytransparency/core/client/verifier"
	"github.com/google/keytransparency/core/mutator/entry"

	"github.com/google/trillian/client/backoff"
	"github.com/google/trillian/types"

	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// TODO: Public keys of trusted monitors.

var (
	// ErrRetry occurs when an update has been queued, but the
	// results of the update differ from the one requested.
	// This indicates that a separate update was in-flight while
	// this update was being submitted. To continue, the client
	// should make a fresh update and try again.
	ErrRetry = status.Errorf(codes.FailedPrecondition, "client: update race condition - try again")
	// ErrWait occurs when an update has been queued, but no change has been
	// observed in the user's account yet.
	ErrWait = status.Errorf(codes.Unavailable, "client: update not present yet - wait some more")
	// ErrIncomplete occurs when the server indicates that requested revisions
	// are not available.
	ErrIncomplete = errors.New("incomplete account history")
	// ErrLogEmpty occurs when the Log.TreeSize < 1 which indicates
	// that the log of signed map roots is empty.
	ErrLogEmpty = errors.New("log is empty - directory initialization failed")
	// ErrNonContiguous occurs when there are holes in a list of map roots.
	ErrNonContiguous = errors.New("noncontiguous map roots")
	// Vlog is the verbose logger. By default it outputs to /dev/null.
	Vlog = log.New(ioutil.Discard, "", 0)
)

// VerifierInterface is used to verify specific outputs from Key Transparency.
type VerifierInterface interface {
	verifier.LogTracker
	// Index computes the index of a userID from a VRF proof, obtained from the server.
	Index(vrfProof []byte, directoryID, userID string) ([]byte, error)
	// VerifyMapRevision verifies that the map revision is correctly signed and included in the log.
	VerifyMapRevision(lr *types.LogRootV1, smr *pb.MapRoot) (*types.MapRootV1, error)
	// VerifyMapLeaf verifies everything about a MapLeaf.
	VerifyMapLeaf(directoryID, userID string, in *pb.MapLeaf, smr *types.MapRootV1) error
	//
	// Pair Verifiers
	//

	// VerifyGetUser verifies the request and response to the GetUser API.
	VerifyGetUser(req *pb.GetUserRequest, resp *pb.GetUserResponse) error
	// VerifyBatchGetUser verifies the request and response to the BatchGetUser API.
	VerifyBatchGetUser(req *pb.BatchGetUserRequest, resp *pb.BatchGetUserResponse) error
}

// ReduceMutationFn takes all the mutations for an index and an auxiliary input
// of existing mapleaf(s) returns a new map leaf.  ReduceMutationFn must be
// idempotent, commutative, and associative. i.e. must produce the same output
// regardless of input order or grouping, and it must be safe to run multiple
// times.
type ReduceMutationFn func(msgs []*pb.EntryUpdate, leaves []*pb.EntryUpdate,
	emit func(*pb.EntryUpdate), emitErr func(error))

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
	VerifierInterface
	cli         pb.KeyTransparencyClient
	DirectoryID string
	reduce      ReduceMutationFn
	RetryDelay  time.Duration
}

// NewFromConfig creates a new client from a config
func NewFromConfig(ktClient pb.KeyTransparencyClient, config *pb.Directory,
	trackerFactory verifier.LogTrackerFactory) (*Client, error) {
	ktVerifier, err := verifier.NewFromDirectory(config, trackerFactory)
	if err != nil {
		return nil, err
	}
	minInterval, err := ptypes.Duration(config.MinInterval)
	if err != nil {
		return nil, err
	}

	return New(ktClient, config.DirectoryId, minInterval, ktVerifier), nil
}

// New creates a new client.
func New(ktClient pb.KeyTransparencyClient,
	directoryID string,
	retryDelay time.Duration,
	ktVerifier VerifierInterface) *Client {
	return &Client{
		VerifierInterface: ktVerifier,
		cli:               ktClient,
		DirectoryID:       directoryID,
		reduce:            entry.ReduceFn,
		RetryDelay:        retryDelay,
	}
}

// GetUser returns an entry if it exists, and nil if it does not.
func (c *Client) GetUser(ctx context.Context, userID string, opts ...grpc.CallOption) (
	*types.MapRootV1, []byte, error) {
	smr, e, err := c.VerifiedGetUser(ctx, userID)
	return smr, e.GetCommitted().GetData(), err
}

// PaginateHistory iteratively calls ListHistory to satisfy the start and end requirements.
// Returns a list of map roots and profiles at each revision.
func (c *Client) PaginateHistory(ctx context.Context, userID string, start, end int64) (
	map[uint64]*types.MapRootV1, map[uint64][]byte, error) {
	if start < 0 {
		return nil, nil, fmt.Errorf("start=%v, want >= 0", start)
	}
	allRoots := make(map[uint64]*types.MapRootV1)
	allProfiles := make(map[uint64][]byte)
	revisionsWant := end - start + 1
	for int64(len(allProfiles)) < revisionsWant {
		count := revisionsWant - int64(len(allProfiles))
		profiles, next, err := c.VerifiedListHistory(ctx, userID, start, int32(count))
		if err != nil {
			return nil, nil, fmt.Errorf("client: VerifiedListHistory(%v, %v): %v", start, count, err)
		}
		for r, d := range profiles {
			allRoots[r.Revision] = r
			allProfiles[r.Revision] = d
		}

		if next == 0 {
			break // No more data.
		}
		start = next // Fetch the next block of results.
	}

	if int64(len(allProfiles)) < revisionsWant {
		glog.Infof("PaginateHistory(): incomplete. Got %v profiles, wanted %v", len(allProfiles), revisionsWant)
		return nil, nil, ErrIncomplete
	}

	return allRoots, allProfiles, nil
}

// CompressHistory takes a map of data by revision number.
// CompressHistory returns only the revisions where the associated data changed.
// CompressHistory returns an error if the list of revisions is not contiguous.
func CompressHistory(profiles map[uint64][]byte) (map[uint64][]byte, error) {
	// Sort map roots.
	revisions := make(uint64Slice, 0, len(profiles))
	for p := range profiles {
		revisions = append(revisions, p)
	}
	sort.Sort(revisions)

	// Compress profiles that are equal through time.  All
	// nil profiles before the first profile are ignored.
	var prevData []byte
	var prevRevision uint64
	ret := make(map[uint64][]byte)
	for i, r := range revisions {
		// Verify that the roots are contiguous
		if i != 0 && r != prevRevision+1 {
			glog.Errorf("Non contiguous history. Got revision %v, want %v", r, prevRevision+1)
			return nil, ErrNonContiguous
		}
		prevRevision = r

		// Append to output when data changes.
		data := profiles[r]
		if bytes.Equal(data, prevData) {
			continue
		}
		prevData = data
		ret[r] = data
	}
	return ret, nil
}

// uint64Slice satisfies sort.Interface.
type uint64Slice []uint64

func (m uint64Slice) Len() int           { return len(m) }
func (m uint64Slice) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m uint64Slice) Less(i, j int) bool { return m[i] < m[j] }

// Update creates and submits a mutation for a user, and waits for it to appear.
// Returns codes.FailedPrecondition if there was a race condition.
func (c *Client) Update(ctx context.Context, u *User, signers []tink.Signer, opts ...grpc.CallOption) (*entry.Mutation, error) {
	// 1. pb.User + ExistingEntry -> Mutation.
	m, err := c.CreateMutation(ctx, u)
	if err != nil {
		return nil, err
	}

	// 2. Queue Mutation.
	if err := c.QueueMutation(ctx, m, signers, opts...); err != nil {
		return nil, err
	}

	// 3. Wait for update.
	return c.WaitForUserUpdate(ctx, m)
}

// QueueMutation signs an entry.Mutation and sends it to the server.
func (c *Client) QueueMutation(ctx context.Context, m *entry.Mutation, signers []tink.Signer, opts ...grpc.CallOption) error {
	update, err := m.SerializeAndSign(signers)
	if err != nil {
		return fmt.Errorf("failed SerializeAndSign: %v", err)
	}

	Vlog.Printf("Sending Update request...")
	req := &pb.UpdateEntryRequest{DirectoryId: c.DirectoryID, EntryUpdate: update}
	_, err = c.cli.QueueEntryUpdate(ctx, req, opts...)
	return err
}

// CreateMutation fetches the current index and value for a user and prepares a mutation.
func (c *Client) CreateMutation(ctx context.Context, u *User) (*entry.Mutation, error) {
	smr, e, err := c.VerifiedGetUser(ctx, u.UserID)
	if err != nil {
		return nil, err
	}
	oldLeaf := e.GetMapInclusion().GetLeaf().GetLeafValue()
	Vlog.Printf("Got current entry...")

	index, err := c.Index(e.GetVrfProof(), c.DirectoryID, u.UserID)
	if err != nil {
		return nil, err
	}

	mutation := entry.NewMutation(index, c.DirectoryID, u.UserID)

	if err := mutation.SetPrevious(smr.Revision, oldLeaf, true); err != nil {
		return nil, err
	}

	if err := mutation.SetCommitment(u.PublicKeyData); err != nil {
		return nil, err
	}

	if u.AuthorizedKeys != nil {
		if err := mutation.ReplaceAuthorizedKeys(u.AuthorizedKeys); err != nil {
			return nil, err
		}
	}

	return mutation, nil
}

// WaitForUserUpdate waits for the mutation to be applied or the context to timeout or cancel.
func (c *Client) WaitForUserUpdate(ctx context.Context, m *entry.Mutation) (*entry.Mutation, error) {
	for {
		m, err := c.waitOnceForUserUpdate(ctx, m)
		switch {
		case err == ErrWait:
			// Try again.
		case status.Code(err) == codes.DeadlineExceeded:
			// Sometimes the timeout occurs during an rpc. Convert to a
			// standard context.DeadlineExceeded for consistent error handling.
			return m, context.DeadlineExceeded
		default:
			return m, err
		}
	}
}

// waitOnceForUserUpdate waits for the STH to be updated, indicating the next revision has been created,
// it then queries the current value for the user and checks it against the requested mutation.
// If the current value has not changed, WaitForUpdate returns ErrWait.
// If the current value has changed, but does not match the requested mutation,
// WaitForUpdate returns a new mutation, built with the current value and ErrRetry.
// If the current value matches the request, no mutation and no error are returned.
func (c *Client) waitOnceForUserUpdate(ctx context.Context, m *entry.Mutation) (*entry.Mutation, error) {
	if m == nil {
		return nil, fmt.Errorf("nil mutation")
	}
	// Wait for STH to change.
	if err := c.WaitForSTHUpdate(ctx, m.MinApplyRevision()); err != nil {
		return m, err
	}

	// GetUser.
	smr, e, err := c.VerifiedGetUser(ctx, m.UserID)
	if err != nil {
		return m, err
	}
	Vlog.Printf("Got current entry...")

	// Verify.
	cntLeaf := e.GetMapInclusion().GetLeaf().GetLeafValue()
	cntValue, err := entry.FromLeafValue(cntLeaf)
	if err != nil {
		return m, err
	}
	switch {
	case m.EqualsRequested(cntValue):
		return nil, nil
	case m.EqualsPrevious(cntValue):
		return m, ErrWait
	default:
		// Race condition: some change got in first.
		// Value has changed, but it's not what we asked for.
		// Retry based on new cntValue.

		// To break the tie between two devices that are fighting
		// each other, this error should be propagated back to the user.
		copyPreviousLeafData := false
		if err := m.SetPrevious(smr.Revision, cntLeaf, copyPreviousLeafData); err != nil {
			return nil, fmt.Errorf("waitforupdate: SetPrevious(): %v", err)
		}
		return m, ErrRetry
	}
}

// sthForRevision returns the minimum STH.TreeSize that will contain the map revision.
// Map revision N is stored at Log index N, the minimum TreeSize will be N+1.
func sthForRevision(revision int64) int64 {
	return revision + 1
}

// mapRevisionFor returns the latest map revision, given the latest sth.
// The log is the authoritative source of the latest revision.
func mapRevisionFor(sth *types.LogRootV1) (uint64, error) {
	// The revision of the map is its index in the log.
	if sth.TreeSize < 1 {
		return 0, ErrLogEmpty
	}

	// TreeSize = maxIndex + 1 because the log starts at index 0.
	maxIndex := sth.TreeSize - 1
	return maxIndex, nil
}

// WaitForRevision waits until a given map revision is available.
func (c *Client) WaitForRevision(ctx context.Context, revision int64) error {
	return c.WaitForSTHUpdate(ctx, sthForRevision(revision))
}

// WaitForSTHUpdate blocks until the log root reported by the server has moved
// to at least treeSize or times out.
func (c *Client) WaitForSTHUpdate(ctx context.Context, treeSize int64) error {
	b := &backoff.Backoff{
		Min:    c.RetryDelay,
		Max:    1 * time.Minute,
		Factor: 1.1,
		Jitter: true,
	}

	for {
		select {
		case <-time.After(b.Duration()):
			logRoot, _, err := c.VerifiedGetLatestRevision(ctx)
			if err != nil {
				return err
			}
			if int64(logRoot.TreeSize) >= treeSize {
				return nil // We're done!
			}
			// The LogRoot is not updated yet.
			// Wait some more.
			continue

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
