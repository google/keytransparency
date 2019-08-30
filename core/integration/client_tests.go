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
	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/client/verifier"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/trillian/types"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
	tclient "github.com/google/trillian/client"
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

func runBatchAndPublish(ctx context.Context, env *Env, mn, mx int32, block bool) error {
	convert := func(err error, prefix string) error {
		if err != nil && err != context.Canceled && status.Code(err) != codes.Canceled {
			st := status.Convert(err)
			return status.Errorf(st.Code(), "%v: %v", prefix, err)
		}
		return err
	}

	drReq := &spb.DefineRevisionsRequest{
		DirectoryId: env.Directory.DirectoryId,
		MinBatch:    mn,
		MaxBatch:    mx,
	}
	if _, err := env.Sequencer.DefineRevisions(ctx, drReq); err != nil {
		return convert(err, "DefineRevisions()")
	}
	arReq := &spb.ApplyRevisionsRequest{DirectoryId: env.Directory.DirectoryId}
	if _, err := env.Sequencer.ApplyRevisions(ctx, arReq); err != nil {
		return convert(err, "ApplyRevisions()")
	}
	prReq := &spb.PublishRevisionsRequest{
		DirectoryId: env.Directory.DirectoryId,
		Block:       block,
	}
	_, err := env.Sequencer.PublishRevisions(ctx, prReq)
	return convert(err, "PublishRevisions()")
}

func runSequencer(ctx context.Context, t *testing.T, env *Env) {
	t.Helper()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	sequencer.PeriodicallyRun(ctx, ticker.C, func(ctx context.Context) {
		err := runBatchAndPublish(ctx, env, 1, 10, false)
		if err != nil && err != context.Canceled && status.Code(err) != codes.Canceled {
			t.Error(err)
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
func TestBatchCreate(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	go runSequencer(ctx, t, env)
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1)

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
			users := make([]*client.User, 0, len(tc.userIDs))
			for _, userID := range tc.userIDs {
				users = append(users, &client.User{
					UserID:         userID,
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
func TestBatchUpdate(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	go runSequencer(ctx, t, env)
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1)

	for _, tc := range []struct {
		desc    string
		userIDs []string
	}{
		{desc: "zero", userIDs: nil},
		{desc: "one", userIDs: []string{"test"}},
		// TODO: Increase batch size once google/trillian#1396 is fixed.
		{desc: "10", userIDs: genUserIDs(10)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Update profiles.
			users := make([]*client.User, 0, len(tc.userIDs))
			for _, userID := range tc.userIDs {
				users = append(users, &client.User{
					UserID:         userID,
					PublicKeyData:  []byte("data!"),
					AuthorizedKeys: authorizedKeys1,
				})
			}

			mutations, err := env.Client.BatchCreateMutation(ctx, users)
			if err != nil {
				t.Fatalf("BatchCreateMutation(): %v", err)
			}
			if err := env.Client.BatchQueueUserUpdate(ctx, mutations, signers1); err != nil {
				t.Fatalf("BatchQueueUserUpdate(): %v", err)
			}
		})
	}
	return nil
}

// TestEmptyGetAndUpdate verifies set/get semantics.
func TestEmptyGetAndUpdate(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	go runSequencer(ctx, t, env)

	cli, err := client.NewFromConfig(env.Cli, env.Directory,
		func(lv *tclient.LogVerifier) verifier.LogTracker {
			t := tracker.NewSynchronous(lv)
			t.SetUpdatePredicate(func(_, newRoot types.LogRootV1) bool {
				// Only update occasionally in order to produce interesting consistency proofs.
				return newRoot.TreeSize%5 == 1
			})
			return t
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	// Create lists of signers.
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	signers2 := testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2)
	signers3 := testutil.SignKeysetsFromPEMs("", testPrivKey2)

	// Create lists of authorized keys
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1)
	authorizedKeys2 := testutil.VerifyKeysetFromPEMs(testPubKey1, testPubKey2)
	authorizedKeys3 := testutil.VerifyKeysetFromPEMs("", testPubKey2)

	// Collect a list of valid GetUserResponses
	transcript := []*tpb.Action{}

	for _, tc := range []struct {
		desc           string
		wantProfile    []byte
		setProfile     []byte
		opts           []grpc.CallOption
		userID         string
		signers        []tink.Signer
		authorizedKeys *keyset.Handle
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
			logReq := cli.LastVerifiedLogRoot()
			req := &pb.GetUserRequest{
				DirectoryId:  env.Directory.DirectoryId,
				UserId:       tc.userID,
				LastVerified: logReq,
			}
			resp, err := env.Cli.GetUser(ctx, req)
			if err != nil {
				t.Fatal(err)
			}
			if err := cli.VerifyGetUser(req, resp); err != nil {
				t.Fatal(err)
			}
			if got, want := resp.GetLeaf().GetCommitted().GetData(), tc.wantProfile; !bytes.Equal(got, want) {
				t.Errorf("VerifiedGetUser(%v): %s, want %s", tc.userID, got, want)
			}

			transcript = append(transcript, &tpb.Action{
				Desc: tc.desc,
				ReqRespPair: &tpb.Action_GetUser{GetUser: &tpb.GetUser{
					Request:  req,
					Response: resp,
				}},
			})

			// Update profile.
			if tc.setProfile != nil {
				u := &client.User{
					UserID:         tc.userID,
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
	return transcript
}

// TestBatchGetUser tests fetching multiple users in a single request.
func TestBatchGetUser(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	go runSequencer(ctx, t, env)
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1)
	transcript := []*tpb.Action{}

	cli, err := client.NewFromConfig(env.Cli, env.Directory,
		func(lv *tclient.LogVerifier) verifier.LogTracker {
			t := tracker.NewSynchronous(lv)
			t.SetUpdatePredicate(func(_, newRoot types.LogRootV1) bool {
				// Only update occasionally in order to produce interesting consistency proofs.
				return newRoot.TreeSize%5 == 1
			})
			return t
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	users := []*client.User{
		{
			UserID:         "bob",
			PublicKeyData:  []byte("bob-key"),
			AuthorizedKeys: authorizedKeys1,
		},
		{
			UserID:         "carol",
			PublicKeyData:  []byte("carol-key"),
			AuthorizedKeys: authorizedKeys1,
		},
	}
	cctx, cancel := context.WithTimeout(ctx, env.Timeout)
	defer cancel()
	if err := env.Client.BatchCreateUser(cctx, users, signers1); err != nil {
		t.Fatalf("BatchCreateUser(): %v", err)
	}
	if err := env.Client.WaitForRevision(cctx, 1); err != nil {
		t.Fatalf("WaitForSTHUpdate(): %v", err)
	}

	for _, tc := range []struct {
		desc         string
		wantProfiles map[string][]byte
	}{
		{
			desc: "single empty",
			wantProfiles: map[string][]byte{
				"alice": nil,
			},
		},
		{
			desc: "multi empty",
			wantProfiles: map[string][]byte{
				"alice": nil,
				"zelda": nil,
			},
		},
		{
			desc: "single full",
			wantProfiles: map[string][]byte{
				"bob": []byte("bob-key"),
			},
		},
		{
			desc: "multi full",
			wantProfiles: map[string][]byte{
				"bob":   []byte("bob-key"),
				"carol": []byte("carol-key"),
			},
		},
		{
			desc: "multi mixed",
			wantProfiles: map[string][]byte{
				"alice": nil,
				"bob":   []byte("bob-key"),
			},
		}} {
		t.Run(tc.desc, func(t *testing.T) {
			userIDs := make([]string, 0)
			for userID := range tc.wantProfiles {
				userIDs = append(userIDs, userID)
			}
			logReq := cli.LastVerifiedLogRoot()
			req := &pb.BatchGetUserRequest{
				DirectoryId:  env.Directory.DirectoryId,
				UserIds:      userIDs,
				LastVerified: logReq,
			}
			resp, err := env.Cli.BatchGetUser(cctx, req)
			if err != nil {
				t.Fatalf("BatchGetUser(): %v", err)
			}
			if err := cli.VerifyBatchGetUser(req, resp); err != nil {
				t.Fatal(err)
			}
			for userID, leaf := range resp.MapLeavesByUserId {
				if got, want := leaf.GetCommitted().GetData(), tc.wantProfiles[userID]; !bytes.Equal(got, want) {
					t.Fatalf("key mismatch for %s: %s, want %s", userID, got, want)
				}
			}

			transcript = append(transcript, &tpb.Action{
				Desc: tc.desc,
				ReqRespPair: &tpb.Action_BatchGetUser{
					BatchGetUser: &tpb.BatchGetUser{
						Request:  req,
						Response: resp,
					},
				},
			})
		})
	}
	return transcript
}

// TestListHistory verifies that repeated history values get collapsed properly.
func TestListHistory(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	userID := "bob"
	opts := env.CallOpts(userID)

	// Create lists of signers and authorized keys
	signers := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys := testutil.VerifyKeysetFromPEMs(testPubKey1)

	if err := env.setupHistory(ctx, userID, signers, authorizedKeys, opts); err != nil {
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

func (env *Env) setupHistory(ctx context.Context, userID string, signers []tink.Signer,
	authorizedKeys *keyset.Handle, opts []grpc.CallOption) error {
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
		if p == nil { // Create an empty revision.
			if err := runBatchAndPublish(ctx, env, 0, 0, false); err != nil {
				return fmt.Errorf("runBatchAndPublish(empty): %v", err)
			}
			continue
		}
		u := &client.User{
			UserID:         userID,
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
		if err := runBatchAndPublish(ctx, env, 1, 1, true); err != nil {
			return fmt.Errorf("runBatchAndPublish(%v): %v", i, err)
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
func TestBatchListUserRevisions(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	// Create lists of signers and authorized keys
	signers := testutil.SignKeysetsFromPEMs(testPrivKey1)
	authorizedKeys := testutil.VerifyKeysetFromPEMs(testPubKey1)

	if err := env.setupHistoryMultipleUsers(ctx, signers, authorizedKeys); err != nil {
		t.Fatalf("setupHistoryMultipleUsers failed: %v", err)
	}

	request := &pb.BatchListUserRevisionsRequest{
		DirectoryId: env.Directory.DirectoryId,
	}
	transcript := []*tpb.Action{}
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
			transcript = append(transcript, &tpb.Action{
				Desc: tc.desc,
				ReqRespPair: &tpb.Action_BatchListUserRevisions{
					BatchListUserRevisions: &tpb.BatchListUserRevisions{
						Request:  request,
						Response: response,
					},
				},
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
	return transcript
}

func (env *Env) setupHistoryMultipleUsers(ctx context.Context, signers []tink.Signer,
	authorizedKeys *keyset.Handle) error {
	// Test setup: 3 different users ("alice", "bob", and "carol") submit profiles in the following order. Specifically, in the i-th submission (i = 0, 1, 2,..., 9), userIDs[i] submits publicKeyData[i].
	publicKeyData := [][]byte{cp(1), cp(11), cp(2), cp(21), cp(22), cp(12), cp(3), cp(13), cp(23), cp(24)}
	userIDs := []string{"alice", "bob", "alice", "carol", "carol", "bob", "alice", "bob", "carol", "carol"}
	for i := 0; i < len(userIDs); i++ {
		u := &client.User{
			UserID:         userIDs[i],
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
		if err := runBatchAndPublish(ctx, env, 1, 1, true); err != nil {
			return fmt.Errorf("runBatchAndPublish(%v): %v", i, err)
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
