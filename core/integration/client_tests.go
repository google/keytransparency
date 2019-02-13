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

package integration

import (
	"bytes"
	"context"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/trillian/types"

	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBoLpoKGPbrFbEzF/ZktBSuGP+Llmx2wVKSkbdAdQ+3JoAoGCCqGSM49
AwEHoUQDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4hnGbXDPbdFlL1nmayhnqyEfR
dXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4
hnGbXDPbdFlL1nmayhnqyEfRdXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END PUBLIC KEY-----`
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGugtYzUjyysX/JtjAFA6K3SzgBSmNjog/3e//VWRLQQoAoGCCqGSM49
AwEHoUQDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQbLOA+tLe/MbwZ69SRdG6Rx92f
9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey2 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQb
LOA+tLe/MbwZ69SRdG6Rx92f9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END PUBLIC KEY-----`
)

func runSequencer(ctx context.Context, t *testing.T, dirID string, env *Env) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	sequencer.PeriodicallyRun(ctx, ticker.C, func(ctx context.Context) {
		if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
			DirectoryId: dirID,
			MinBatch:    1,
			MaxBatch:    10,
		}); err != nil && err != context.Canceled && status.Code(err) != codes.Canceled {
			t.Errorf("RunBatch(): %v", err)
		}
	})
}

func genUserIDs(count int) []string {
	userIDs := make([]string, 0, count)
	for i := 0; i < count; i++ {
		userIDs = append(userIDs, fmt.Sprintf("user %v", i))
	}
	return userIDs
}

// TestBatchCreate verifies that the batch functions are working correctly.
func TestBatchCreate(ctx context.Context, env *Env, t *testing.T) []testdata.ResponseVector {
	go runSequencer(ctx, t, env.Directory.DirectoryId, env)
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	for _, tc := range []struct {
		desc    string
		userIDs []string
	}{
		{desc: "zero", userIDs: nil},
		{desc: "one", userIDs: []string{"test"}},
		{desc: "100", userIDs: genUserIDs(100)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Update profiles.
			users := make([]*tpb.User, 0, len(tc.userIDs))
			for _, userID := range tc.userIDs {
				users = append(users, &tpb.User{
					UserId:         userID,
					PublicKeyData:  []byte("data!"),
					AuthorizedKeys: authorizedKeys1,
				})
			}

			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()
			if err := env.Client.BatchCreateUser(cctx, users, signers1); err != nil {
				t.Fatalf("BatchCreateUser(): %v", err)
			}
		})
	}
	return nil
}

// TestBatchUpdate verifies that the batch functions are working correctly.
func TestBatchUpdate(ctx context.Context, env *Env, t *testing.T) []testdata.ResponseVector {
	go runSequencer(ctx, t, env.Directory.DirectoryId, env)
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	for _, tc := range []struct {
		desc    string
		userIDs []string
	}{
		{desc: "zero", userIDs: nil},
		{desc: "one", userIDs: []string{"test"}},
		{desc: "100", userIDs: genUserIDs(100)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Update profiles.
			users := make([]*tpb.User, 0, len(tc.userIDs))
			for _, userID := range tc.userIDs {
				users = append(users, &tpb.User{
					UserId:         userID,
					PublicKeyData:  []byte("data!"),
					AuthorizedKeys: authorizedKeys1,
				})
			}

			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()

			mutations, err := env.Client.BatchCreateMutation(cctx, users)
			if err != nil {
				t.Fatalf("BatchCreateMutation(): %v", err)
			}
			if err := env.Client.BatchQueueUserUpdate(cctx, mutations, signers1); err != nil {
				t.Fatalf("BatchQueueUserUpdate(): %v", err)
			}
		})
	}
	return nil
}

// TestEmptyGetAndUpdate verifies set/get semantics.
func TestEmptyGetAndUpdate(ctx context.Context, env *Env, t *testing.T) []testdata.ResponseVector {
	go runSequencer(ctx, t, env.Directory.DirectoryId, env)

	// Create lists of signers.
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	signers2 := testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2)
	signers3 := testutil.SignKeysetsFromPEMs("", testPrivKey2)

	// Create lists of authorized keys
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()
	authorizedKeys2 := testutil.VerifyKeysetFromPEMs(testPubKey1, testPubKey2).Keyset()
	authorizedKeys3 := testutil.VerifyKeysetFromPEMs("", testPubKey2).Keyset()

	// Collect a list of valid GetUserResponses
	getUserResps := make([]testdata.ResponseVector, 0)

	// Start with an empty trusted log root
	slr := &types.LogRootV1{}

	for _, tc := range []struct {
		desc           string
		wantProfile    []byte
		setProfile     []byte
		opts           []grpc.CallOption
		userID         string
		signers        []tink.Signer
		authorizedKeys *tinkpb.Keyset
	}{
		{
			desc:           "empty_alice",
			wantProfile:    nil,
			setProfile:     []byte("alice-key1"),
			opts:           env.CallOpts("alice"),
			userID:         "alice",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob0_set",
			wantProfile:    nil,
			setProfile:     []byte("bob-key1"),
			opts:           env.CallOpts("bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "set_carol",
			wantProfile:    nil,
			setProfile:     []byte("carol-key1"),
			opts:           env.CallOpts("carol"),
			userID:         "carol",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob1_get",
			wantProfile:    []byte("bob-key1"),
			setProfile:     nil,
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob1_set",
			wantProfile:    []byte("bob-key1"),
			setProfile:     []byte("bob-key2"),
			opts:           env.CallOpts("bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob2_setkeys",
			wantProfile:    []byte("bob-key2"),
			setProfile:     []byte("bob-key3"),
			opts:           env.CallOpts("bob"),
			userID:         "bob",
			signers:        signers2,
			authorizedKeys: authorizedKeys2,
		},
		{
			desc:           "bob3_setnewkeys",
			wantProfile:    []byte("bob-key3"),
			setProfile:     []byte("bob-key4"),
			opts:           env.CallOpts("bob"),
			userID:         "bob",
			signers:        signers3,
			authorizedKeys: authorizedKeys3,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Check profile.
			e, newslr, err := CheckProfile(ctx, env, tc.userID, tc.wantProfile, slr)
			if err != nil {
				t.Errorf("%v", err)
			}

			// Update the trusted root on the first revision, then let it fall behind
			// every few revisions to make consistency proofs more interesting.
			trust := newslr.TreeSize%5 == 1
			if trust {
				slr = newslr
			}
			getUserResps = append(getUserResps, testdata.ResponseVector{
				Desc:        tc.desc,
				UserIDs:     []string{tc.userID},
				GetUserResp: e,
				TrustNewLog: trust,
			})

			// Update profile.
			if tc.setProfile != nil {
				u := &tpb.User{
					UserId:         tc.userID,
					PublicKeyData:  tc.setProfile,
					AuthorizedKeys: tc.authorizedKeys,
				}
				cctx, cancel := context.WithTimeout(ctx, env.Timeout)
				defer cancel()
				_, err := env.Client.Update(cctx, u, tc.signers)
				if err != nil {
					t.Errorf("Update(%v): %v", tc.userID, err)
				}
			}
		})
	}
	return getUserResps
}

// CheckProfile verifies that the retrieved profile of userID is correct.
func CheckProfile(ctx context.Context, env *Env, userID string, wantProfile []byte, slr *types.LogRootV1) (*pb.GetUserResponse, *types.LogRootV1, error) {
	e, err := env.Cli.GetUser(ctx, &pb.GetUserRequest{
		DirectoryId:          env.Directory.DirectoryId,
		UserId:               userID,
		LastVerifiedTreeSize: int64(slr.TreeSize),
	})
	if err != nil {
		return nil, nil, fmt.Errorf("getUser(%v): %v, want nil", userID, err)
	}
	newslr, smr, err := env.Client.VerifyRevision(e.Revision, *slr)
	if err != nil {
		return nil, nil, fmt.Errorf("verifyRevision() for user %v: %v, want nil", userID, err)
	}
	if err := env.Client.VerifyMapLeaf(env.Directory.DirectoryId, userID, e.Leaf, smr); err != nil {
		return nil, nil, fmt.Errorf("verifyMapLeaf() for user %v: %v, want nil", userID, err)
	}
	if got, want := e.GetLeaf().GetCommitted().GetData(), wantProfile; !bytes.Equal(got, want) {
		return nil, nil, fmt.Errorf("verifiedGetUser(%v): %s, want %s", userID, got, want)
	}
	return e, newslr, nil
}

// TestListHistory verifies that repeated history values get collapsed properly.
func TestListHistory(ctx context.Context, env *Env, t *testing.T) []testdata.ResponseVector {
	userID := "bob"
	opts := env.CallOpts(userID)

	// Create lists of signers and authorized keys
	signers := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	if err := env.setupHistory(ctx, env.Directory, userID, signers, authorizedKeys, opts); err != nil {
		t.Fatalf("setupHistory failed: %v", err)
	}

	for _, tc := range []struct {
		desc        string
		start, end  int64
		wantHistory [][]byte
		wantErr     bool
	}{
		{desc: "negative start", start: -1, end: 1, wantHistory: [][]byte{}, wantErr: true},
		{desc: "large end", start: 1, end: 1001, wantHistory: [][]byte{}, wantErr: true},
		{desc: "single1", start: 3, end: 3, wantHistory: [][]byte{cp(1)}},
		{desc: "single3", start: 7, end: 7, wantHistory: [][]byte{cp(3)}},
		{desc: "single3", start: 8, end: 8, wantHistory: [][]byte{cp(3)}},
		{desc: "0to3", end: 3, wantHistory: [][]byte{cp(1)}},
		{desc: "multi", end: 4, wantHistory: [][]byte{cp(1), cp(2)}},
		{desc: "filter nil", end: 11, wantHistory: [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5)}},
		{desc: "filter dup", start: 9, end: 16, wantHistory: [][]byte{cp(4), cp(5), cp(6)}},
		{desc: "filter contiguous", start: 9, end: 19, wantHistory: [][]byte{cp(4), cp(5), cp(6), cp(5), cp(7)}},
		{desc: "multi page", start: 1, end: 19, wantHistory: [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5), cp(6), cp(5), cp(7)}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			_, resp, err := env.Client.PaginateHistory(ctx, userID, tc.start, tc.end)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("ListHistory(%v, %v) failed: %v, wantErr :%v", tc.start, tc.end, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			compressed, err := client.CompressHistory(resp)
			if err != nil {
				t.Errorf("CompressHistory(): %v", err)
			}

			if got := sortHistory(compressed); !reflect.DeepEqual(got, tc.wantHistory) {
				t.Errorf("ListHistory(%v, %v): %s, want %s", tc.start, tc.end, got, tc.wantHistory)
			}
		})
	}
	return nil
}

func (env *Env) setupHistory(ctx context.Context, directory *pb.Directory, userID string, signers []tink.Signer,
	authorizedKeys *tinkpb.Keyset, opts []grpc.CallOption) error {
	// Setup. Each profile entry is either nil, to indicate that the user
	// did not submit a new profile in that revision, or contains the profile
	// that the user is submitting. The user profile history contains the
	// following profiles:
	// Profile Value: err nil 1  2  2  2  3  3  4  5  5 5 5 5 5 6 6 5 7 7
	// Map Revision:  1  2  3  4  5  6  7  8  9  10 ...
	// Log Max Index: 1  2  3  4  5  6  7  8  9  10 ...
	// Log TreeSize:  2  3  4  5  6  7  8  9  10 11 ...
	// Note that profile 5 is submitted twice by the user to test that
	// filtering case.

	for i, p := range [][]byte{
		nil, nil, cp(1), cp(2), nil, nil, cp(3), nil,
		cp(4), cp(5), cp(5), nil, nil, nil, nil, cp(6),
		nil, cp(5), cp(7), nil,
	} {
		if p != nil {
			u := &tpb.User{
				UserId:         userID,
				PublicKeyData:  p,
				AuthorizedKeys: authorizedKeys,
			}
			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()

			m, err := env.Client.CreateMutation(cctx, u)
			if err != nil {
				return fmt.Errorf("client.CreateMutation(%v): %v", userID, err)
			}
			if err := env.Client.QueueMutation(ctx, m, signers, opts...); err != nil {
				return fmt.Errorf("sequencer.QueueMutation(): %v", err)
			}
			if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
				DirectoryId: directory.DirectoryId,
				MinBatch:    1,
				MaxBatch:    1,
				Block:       true,
			}); err != nil {
				return fmt.Errorf("sequencer.RunBatch(%v): %v", i, err)
			}
		} else if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
			DirectoryId: directory.DirectoryId,
			// Create an empty revision.
		}); err != nil {
			return fmt.Errorf("sequencer.RunBatch(empty): %v", err)
		}
	}
	return nil
}

func sortHistory(history map[uint64][]byte) [][]byte {
	keys := make(uint64Slice, 0, len(history))
	for k := range history {
		keys = append(keys, k)
	}
	sort.Sort(keys)
	profiles := make([][]byte, 0, len(keys))
	for _, k := range keys {
		profiles = append(profiles, history[k])
	}
	return profiles
}

// TestBatchListUserRevisions verifies that BatchListUserRevisions() in keyserver works properly.
func TestBatchListUserRevisions(ctx context.Context, env *Env, t *testing.T) []testdata.ResponseVector {
	// Create lists of signers and authorized keys
	signers := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	if err := env.setupHistoryMultipleUsers(ctx, env.Directory, signers, authorizedKeys); err != nil {
		t.Fatalf("setupHistoryMultipleUsers failed: %v", err)
	}

	request := &pb.BatchListUserRevisionsRequest{
		DirectoryId: env.Directory.DirectoryId,
	}
	responseVec := make([]testdata.ResponseVector, 0)
	for _, tc := range []struct {
		desc        string
		start, end  int64
		userIDs     []string
		wantHistory [][]byte
		wantErr     bool
	}{
		{desc: "negative start", start: -1, end: 1, userIDs: []string{"alice"}, wantHistory: [][]byte{}, wantErr: true},
		{desc: "large end", start: 1, end: 1001, userIDs: []string{"alice"}, wantHistory: [][]byte{}, wantErr: true},
		{desc: "single revision", start: 3, end: 3, userIDs: []string{"alice", "bob"}, wantHistory: [][]byte{cp(2), cp(11)}},
		{desc: "multiple revisions test 1", start: 4, end: 7, userIDs: []string{"carol"},
			wantHistory: [][]byte{cp(21), cp(22), cp(22), cp(22)}},
		{desc: "multiple revisions test 2", start: 7, end: 10, userIDs: []string{"alice", "bob", "carol"},
			wantHistory: [][]byte{cp(3), cp(12), cp(22), cp(3), cp(13), cp(22), cp(3), cp(13), cp(23), cp(3), cp(13), cp(24)}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			request.StartRevision = tc.start
			request.EndRevision = tc.end
			request.UserIds = tc.userIDs
			response, err := env.Cli.BatchListUserRevisions(ctx, request)
			if got := err != nil; got != tc.wantErr {
				t.Errorf("TestBatchListUserRevisions(%v, %v, %v) failed: %v, wantErr :%v", tc.start, tc.end, tc.userIDs, err, tc.wantErr)
			}
			if err != nil {
				return
			}
			responseVec = append(responseVec, testdata.ResponseVector{
				Desc:                       tc.desc,
				UserIDs:                    tc.userIDs,
				BatchListUserRevisionsResp: response,
			})
			var got [][]byte
			for _, rev := range response.MapRevisions {
				for _, userID := range tc.userIDs {
					got = append(got, rev.MapLeavesByUserId[userID].GetCommitted().GetData())
				}
			}
			if !reflect.DeepEqual(got, tc.wantHistory) {
				t.Errorf("TestBatchListUserRevisions(%v, %v, %v): %s, want %s", tc.start, tc.end, tc.userIDs, got, tc.wantHistory)
			}
		})
	}
	return responseVec
}

func (env *Env) setupHistoryMultipleUsers(ctx context.Context, directory *pb.Directory, signers []tink.Signer,
	authorizedKeys *tinkpb.Keyset) error {
	// Test setup: 3 different users ("alice", "bob", and "carol") submit profiles in the following order. Specifically, in the i-th submission (i = 0, 1, 2,..., 9), userIDs[i] submits publicKeyData[i].
	publicKeyData := [][]byte{cp(1), cp(11), cp(2), cp(21), cp(22), cp(12), cp(3), cp(13), cp(23), cp(24)}
	userIDs := []string{"alice", "bob", "alice", "carol", "carol", "bob", "alice", "bob", "carol", "carol"}
	for i := 0; i < len(userIDs); i++ {
		u := &tpb.User{
			UserId:         userIDs[i],
			PublicKeyData:  publicKeyData[i],
			AuthorizedKeys: authorizedKeys,
		}
		cctx, cancel := context.WithTimeout(ctx, env.Timeout)
		defer cancel()

		m, err := env.Client.CreateMutation(cctx, u)
		if err != nil {
			return fmt.Errorf("client.CreateMutation(%v): %v", userIDs[i], err)
		}
		if err := env.Client.QueueMutation(ctx, m, signers, env.CallOpts(userIDs[i])...); err != nil {
			return fmt.Errorf("sequencer.QueueMutation(): %v", err)
		}
		if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
			DirectoryId: directory.DirectoryId,
			MinBatch:    1,
			MaxBatch:    1,
			Block:       true,
		}); err != nil {
			return fmt.Errorf("sequencer.RunBatch(%v): %v", i, err)
		}
	}
	return nil
}

// uint64Slice satisfies sort.Interface.
type uint64Slice []uint64

func (m uint64Slice) Len() int           { return len(m) }
func (m uint64Slice) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m uint64Slice) Less(i, j int) bool { return m[i] < m[j] }

// cp creates a dummy profile using the passed tag.
func cp(tag int) []byte {
	return []byte(fmt.Sprintf("bar%v", tag))
}
