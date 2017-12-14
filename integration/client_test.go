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
	"encoding/pem"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/google/keytransparency/core/client/grpcc"
	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/sequencer"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
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

var (
	primaryKey = []byte("bar")
	appID      = "app"
)

func createSigner(t *testing.T, privKey string) signatures.Signer {
	signatures.Rand = dev.Zeros
	signer, err := factory.NewSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Fatalf("factory.NewSigner failed: %v", err)
	}
	return signer
}

func getAuthorizedKey(pubKey string) *keyspb.PublicKey {
	pk, _ := pem.Decode([]byte(pubKey))
	return &keyspb.PublicKey{Der: pk.Bytes}
}

func TestEmptyGetAndUpdate(t *testing.T) {
	bctx := context.Background()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	// Create lists of signers.
	signer1 := createSigner(t, testPrivKey1)
	signers1 := []signatures.Signer{signer1}
	signer2 := createSigner(t, testPrivKey2)
	signers2 := []signatures.Signer{signer1, signer2}
	signers3 := []signatures.Signer{signer2}

	// Create lists of authorized keys
	authorizedKey1 := getAuthorizedKey(testPubKey1)
	authorizedKeys1 := []*keyspb.PublicKey{authorizedKey1}
	authorizedKey2 := getAuthorizedKey(testPubKey2)
	authorizedKeys2 := []*keyspb.PublicKey{authorizedKey1, authorizedKey2}
	authorizedKeys3 := []*keyspb.PublicKey{authorizedKey2}

	for _, tc := range []struct {
		desc           string
		want           bool
		insert         bool
		ctx            context.Context
		userID         string
		signers        []signatures.Signer
		authorizedKeys []*keyspb.PublicKey
	}{
		{
			desc:           "Empty",
			want:           false,
			insert:         false,
			ctx:            context.Background(),
			userID:         "noalice",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "Insert",
			want:           false,
			insert:         true,
			ctx:            GetNewOutgoingContextWithFakeAuth("bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "Empty2",
			want:           false,
			insert:         false,
			ctx:            context.Background(),
			userID:         "nocarol",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "Not Empty",
			want:           true,
			insert:         false,
			ctx:            context.Background(),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "Update",
			want:           true,
			insert:         true,
			ctx:            GetNewOutgoingContextWithFakeAuth("bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "Update, changing keys",
			want:           true,
			insert:         true,
			ctx:            GetNewOutgoingContextWithFakeAuth("bob"),
			userID:         "bob",
			signers:        signers2,
			authorizedKeys: authorizedKeys2,
		},
		{
			desc:           "Update, using new keys",
			want:           true,
			insert:         true,
			ctx:            GetNewOutgoingContextWithFakeAuth("bob"),
			userID:         "bob",
			signers:        signers3,
			authorizedKeys: authorizedKeys3,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Check profile.
			if err := env.checkProfile(tc.userID, appID, tc.want); err != nil {
				t.Errorf("checkProfile(%v, %v) failed: %v", tc.userID, tc.want, err)
			}
			// Update profile.
			if tc.insert {
				m, err := env.Client.Update(tc.ctx, appID, tc.userID, primaryKey, tc.signers, tc.authorizedKeys)
				if got, want := err, grpcc.ErrRetry; got != want {
					t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
				}
				if err := env.Signer.CreateEpoch(bctx, env.Domain.Log.TreeId, env.Domain.Map.TreeId, sequencer.ForceNewEpoch(true)); err != nil {
					t.Errorf("CreateEpoch(_): %v", err)
				}
				if err := env.Client.Retry(tc.ctx, m, tc.signers); err != nil {
					t.Errorf("Retry(%v): %v, want nil", m, err)
				}
			}
		})
	}
}

// checkProfile ensures that the returned profile is as expected along with the
// keys it carries.
func (e *Env) checkProfile(userID, appID string, want bool) error {
	profile, _, err := e.Client.GetEntry(context.Background(), userID, appID)
	if err != nil {
		return fmt.Errorf("GetEntry(%v): %v, want nil", userID, err)
	}
	if got := profile != nil; got != want {
		return fmt.Errorf("GetEntry(%v): %v, want %v", userID, profile, want)
	}
	if want {
		if got, want := profile, primaryKey; !bytes.Equal(got, want) {
			return fmt.Errorf("profile = %x, want: %x", got, want)
		}
	}
	return nil
}

func TestUpdateValidation(t *testing.T) {
	bctx := context.Background()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	profile := []byte("bar")

	// Create lists of signers and authorized keys
	signers := []signatures.Signer{createSigner(t, testPrivKey1)}
	authorizedKeys := []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)}

	for _, tc := range []struct {
		want           bool
		ctx            context.Context
		userID         string
		profile        []byte
		signers        []signatures.Signer
		authorizedKeys []*keyspb.PublicKey
	}{
		{false, context.Background(), "alice", profile, signers, authorizedKeys},
		{false, GetNewOutgoingContextWithFakeAuth("carol"), "bob", profile, signers, authorizedKeys},
		{true, GetNewOutgoingContextWithFakeAuth("dave"), "dave", profile, signers, authorizedKeys},
		{true, GetNewOutgoingContextWithFakeAuth("eve"), "eve", profile, signers, authorizedKeys},
	} {
		m, err := env.Client.Update(tc.ctx, appID, tc.userID, tc.profile, tc.signers, tc.authorizedKeys)

		if tc.want {
			// The first update response is always a retry.
			if got, want := err, grpcc.ErrRetry; got != want {
				t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			if err := env.Signer.CreateEpoch(bctx, env.Domain.Log.TreeId, env.Domain.Map.TreeId, sequencer.ForceNewEpoch(true)); err != nil {
				t.Errorf("CreateEpoch(_): %v", err)
			}
			if err := env.Client.Retry(tc.ctx, m, signers); err != nil {
				t.Errorf("Retry(%v): %v, want nil", m, err)
			}
		} else {
			if got, want := err, grpcc.ErrRetry; got == want {
				t.Fatalf("Update(%v): %v, don't want %v", tc.userID, got, want)
			}
		}
	}
}

func TestListHistory(t *testing.T) {
	userID := "bob"
	ctx := GetNewOutgoingContextWithFakeAuth(userID)

	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	// Create lists of signers and authorized keys
	signers := []signatures.Signer{createSigner(t, testPrivKey1)}
	authorizedKeys := []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)}

	if err := env.setupHistory(ctx, env.Domain, userID, signers, authorizedKeys); err != nil {
		t.Fatalf("setupHistory failed: %v", err)
	}

	for _, tc := range []struct {
		start, end  int64
		wantHistory [][]byte
		wantErr     bool
	}{
		{-1, 1, [][]byte{}, true},                                                        // start epoch < 0: expect error
		{1, 2, [][]byte{}, false},                                                        // no profile yet
		{2, 3, [][]byte{cp(1)}, false},                                                   // single profile (first entry at 3)
		{3, 3, [][]byte{cp(1)}, false},                                                   // single profile (first entry at 3)
		{4, 4, [][]byte{cp(2)}, false},                                                   // single (changed) profile
		{5, 5, [][]byte{cp(2)}, false},                                                   // single (unchanged) profile
		{6, 6, [][]byte{cp(2)}, false},                                                   // single (unchanged) profile
		{7, 7, [][]byte{cp(3)}, false},                                                   // single (changed) profile
		{3, 4, [][]byte{cp(1), cp(2)}, false},                                            // multiple profiles
		{1, 4, [][]byte{cp(1), cp(2)}, false},                                            // test 'nil' first profile(s)
		{3, 10, [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5)}, false},                      // filtering
		{9, 16, [][]byte{cp(4), cp(5), cp(6)}, false},                                    // filtering consecutive resubmitted profiles
		{9, 19, [][]byte{cp(4), cp(5), cp(6), cp(5), cp(7)}, false},                      // no filtering of resubmitted profiles
		{1, 19, [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5), cp(6), cp(5), cp(7)}, false}, // multiple pages
		{1, 1000, [][]byte{}, true},                                                      // Invalid end epoch, beyond current epoch
	} {
		resp, err := env.Client.ListHistory(ctx, userID, appID, tc.start, tc.end)
		if got := err != nil; got != tc.wantErr {
			t.Errorf("ListHistory(%v, %v) failed: %v, wantErr :%v", tc.start, tc.end, err, tc.wantErr)
		}
		if err != nil {
			continue
		}

		if got := sortHistory(resp); !reflect.DeepEqual(got, tc.wantHistory) {
			t.Errorf("ListHistory(%v, %v): %x, want %x", tc.start, tc.end, got, tc.wantHistory)
		}
	}
}

func (e *Env) setupHistory(ctx context.Context, domain *pb.Domain, userID string, signers []signatures.Signer, authorizedKeys []*keyspb.PublicKey) error {
	// Setup. Each profile entry is either nil, to indicate that the user
	// did not submit a new profile in that epoch, or contains the profile
	// that the user is submitting. The user profile history contains the
	// following profiles:
	// Profile Value: err  err nil 1  2  2  2  3  3  4  5  5 5 5 5 5 6 6 5 7 7
	// Map Revision:  err 0  1  2  3  4  5  6  7  8  9  10 ...
	// Log Max Index: err 0  1  2  3  4  5  6  7  8  9  10 ...
	// Log TreeSize:    0 1  2  3  4  5  6  7  8  9  10 11 ...
	// Note that profile 5 is submitted twice by the user to test that
	// filtering case.
	for i, p := range [][]byte{
		nil, cp(1), cp(2), nil, nil, cp(3), nil,
		cp(4), cp(5), cp(5), nil, nil, nil, nil, cp(6),
		nil, cp(5), cp(7), nil,
	} {
		if p != nil {
			_, err := e.Client.Update(ctx, appID, userID, p, signers, authorizedKeys)
			// The first update response is always a retry.
			if got, want := err, grpcc.ErrRetry; got != want {
				return fmt.Errorf("Update(%v, %v)=(_, %v), want (_, %v)", userID, i, got, want)
			}
		}
		if err := e.Signer.CreateEpoch(ctx, domain.Log.TreeId, domain.Map.TreeId, sequencer.ForceNewEpoch(true)); err != nil {
			return fmt.Errorf("CreateEpoch(_): %v", err)
		}
	}
	return nil
}

func sortHistory(history map[*trillian.SignedMapRoot][]byte) [][]byte {
	keys := make([]*trillian.SignedMapRoot, 0, len(history))
	for k := range history {
		keys = append(keys, k)
	}
	sort.Sort(mapHeads(keys))
	profiles := make([][]byte, len(keys))
	for i, k := range keys {
		profiles[i] = history[k]
	}
	return profiles
}

// MapHead sorter.
type mapHeads []*trillian.SignedMapRoot

func (m mapHeads) Len() int           { return len(m) }
func (m mapHeads) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m mapHeads) Less(i, j int) bool { return m[i].MapRevision < m[j].MapRevision }

// cp creates a dummy profile using the passed tag.
func cp(tag int) []byte {
	return []byte(fmt.Sprintf("bar%v", tag))
}

// TODO: Test AppID filtering when implemented.
