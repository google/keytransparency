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
	"github.com/google/keytransparency/core/testutil"

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

// TestEmptyGetAndUpdate verifies set/get semantics.
func TestEmptyGetAndUpdate(ctx context.Context, env *Env, t *testing.T) {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		sequencer.PeriodicallyRun(ctx, ticker.C, func(ctx context.Context) {
			if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
				DirectoryId: env.Directory.DirectoryId,
				MinBatch:    1,
				MaxBatch:    10,
			}); err != nil && err != context.Canceled && status.Code(err) != codes.Canceled {
				t.Errorf("RunBatch(): %v", err)
			}
		})
	}()

	// Create lists of signers.
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)
	signers2 := testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2)
	signers3 := testutil.SignKeysetsFromPEMs("", testPrivKey2)

	// Create lists of authorized keys
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()
	authorizedKeys2 := testutil.VerifyKeysetFromPEMs(testPubKey1, testPubKey2).Keyset()
	authorizedKeys3 := testutil.VerifyKeysetFromPEMs("", testPubKey2).Keyset()

	for _, tc := range []struct {
		desc           string
		wantProfile    []byte
		setProfile     []byte
		opts           []grpc.CallOption
		userID         string
		signers        []*tink.KeysetHandle
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
			e, _, err := env.Client.VerifiedGetUser(ctx, tc.userID)
			if err != nil {
				t.Errorf("VerifiedGetUser(%v): %v, want nil", tc.userID, err)
			}
			if got, want := e.GetLeaf().GetCommitted().GetData(), tc.wantProfile; !bytes.Equal(got, want) {
				t.Errorf("VerifiedGetUser(%v): %s, want %s", tc.userID, got, want)
			}

			// Update profile.
			if tc.setProfile != nil {
				u := &tpb.User{
					DirectoryId:    env.Directory.DirectoryId,
					UserId:         tc.userID,
					PublicKeyData:  tc.setProfile,
					AuthorizedKeys: tc.authorizedKeys,
				}
				cctx, cancel := context.WithTimeout(ctx, env.Timeout)
				defer cancel()

				m, err := env.Client.CreateMutation(cctx, u)
				if err != nil {
					t.Fatalf("CreateMutation(%v): %v", tc.userID, err)
				}
				if err := env.Client.QueueMutation(cctx, m, tc.signers, tc.opts...); err != nil {
					t.Fatalf("QueueMutation(%v): %v", tc.userID, err)
				}

				if _, err := env.Client.WaitForUserUpdate(cctx, m); err != nil {
					t.Errorf("WaitForUserUpdate(%v): %v, want nil", m, err)
				}
			}
		})
	}
}

// TestListHistory verifies that repeated history values get collapsed properly.
func TestListHistory(ctx context.Context, env *Env, t *testing.T) {
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
		{desc: "large start", start: 1, end: 1001, wantHistory: [][]byte{}, wantErr: true},
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
}

func (env *Env) setupHistory(ctx context.Context, directory *pb.Directory, userID string, signers []*tink.KeysetHandle,
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
				DirectoryId:    directory.DirectoryId,
				UserId:         userID,
				PublicKeyData:  p,
				AuthorizedKeys: authorizedKeys,
			}
			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()

			m, err := env.Client.CreateMutation(cctx, u)
			if err != nil {
				return fmt.Errorf("CreateMutation(%v): %v", userID, err)
			}
			if err := env.Client.QueueMutation(ctx, m, signers, opts...); err != nil {
				return fmt.Errorf("sequencer.QueueMutation(): %v", err)
			}
			if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
				DirectoryId: directory.DirectoryId,
				MinBatch:    1,
				MaxBatch:    1,
			}); err != nil {
				return fmt.Errorf("sequencer.RunBatch(%v): %v", i, err)
			}
		} else {
			// Create an empty revision.
			if _, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
				DirectoryId: directory.DirectoryId,
			}); err != nil {
				return fmt.Errorf("sequencer.RunBatch(empty): %v", err)
			}
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

// uint64Slice satisfies sort.Interface.
type uint64Slice []uint64

func (m uint64Slice) Len() int           { return len(m) }
func (m uint64Slice) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m uint64Slice) Less(i, j int) bool { return m[i] < m[j] }

// cp creates a dummy profile using the passed tag.
func cp(tag int) []byte {
	return []byte(fmt.Sprintf("bar%v", tag))
}
