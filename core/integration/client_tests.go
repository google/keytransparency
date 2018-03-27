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

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"

	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/types"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
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
	appID = "app"
)

func createSigner(t *testing.T, privKey string) signatures.Signer {
	signatures.Rand = dev.Zeros
	signer, err := factory.NewSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Fatalf("factory.NewSigner failed: %v", err)
	}
	return signer
}

func getAuthorizedKeys(pubKeys ...string) []*keyspb.PublicKey {
	ret := make([]*keyspb.PublicKey, 0, len(pubKeys))
	for _, pubKey := range pubKeys {
		ret = append(ret, getAuthorizedKey(pubKey))
	}
	return ret
}

func getAuthorizedKey(pubKey string) *keyspb.PublicKey {
	pk, _ := pem.Decode([]byte(pubKey))
	return &keyspb.PublicKey{Der: pk.Bytes}
}

// TestEmptyGetAndUpdate verifies set/get semantics.
func TestEmptyGetAndUpdate(ctx context.Context, env *Env, t *testing.T) {
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
		wantProfile    []byte
		setProfile     []byte
		ctx            context.Context
		userID         string
		signers        []signatures.Signer
		authorizedKeys []*keyspb.PublicKey
	}{
		{
			desc:           "empty_alice",
			wantProfile:    nil,
			setProfile:     []byte("alice-key1"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "alice"),
			userID:         "alice",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob0_set",
			wantProfile:    nil,
			setProfile:     []byte("bob-key1"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "set_carol",
			wantProfile:    nil,
			setProfile:     []byte("carol-key1"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "carol"),
			userID:         "carol",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob1_get",
			wantProfile:    []byte("bob-key1"),
			setProfile:     nil,
			ctx:            context.Background(),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob1_set",
			wantProfile:    []byte("bob-key1"),
			setProfile:     []byte("bob-key2"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "bob"),
			userID:         "bob",
			signers:        signers1,
			authorizedKeys: authorizedKeys1,
		},
		{
			desc:           "bob2_setkeys",
			wantProfile:    []byte("bob-key2"),
			setProfile:     []byte("bob-key3"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "bob"),
			userID:         "bob",
			signers:        signers2,
			authorizedKeys: authorizedKeys2,
		},
		{
			desc:           "bob3_setnewkeys",
			wantProfile:    []byte("bob-key3"),
			setProfile:     []byte("bob-key4"),
			ctx:            authentication.WithOutgoingFakeAuth(ctx, "bob"),
			userID:         "bob",
			signers:        signers3,
			authorizedKeys: authorizedKeys3,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			// Check profile.
			e, _, err := env.Client.VerifiedGetEntry(ctx, appID, tc.userID)
			if err != nil {
				t.Errorf("VerifiedGetEntry(%v): %v, want nil", tc.userID, err)
			}
			if got, want := e.GetCommitted().GetData(), tc.wantProfile; !bytes.Equal(got, want) {
				t.Errorf("VerifiedGetEntry(%v): %s, want %s", tc.userID, got, want)
			}

			// Update profile.
			if tc.setProfile != nil {
				u := &tpb.User{
					DomainId:       env.Domain.DomainId,
					AppId:          appID,
					UserId:         tc.userID,
					PublicKeyData:  tc.setProfile,
					AuthorizedKeys: tc.authorizedKeys,
				}
				cctx, cancel := context.WithTimeout(tc.ctx, env.Timeout)
				defer cancel()
				m, err := env.Client.Update(cctx, u, tc.signers)
				if got, want := err, context.DeadlineExceeded; got != want {
					t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
				}
				cctx, cancel = context.WithTimeout(tc.ctx, env.Timeout)
				defer cancel()
				env.Receiver.Flush(cctx)
				cctx, cancel = context.WithTimeout(tc.ctx, env.Timeout)
				defer cancel()
				if _, err := env.Client.WaitForUserUpdate(cctx, m); err != nil {
					t.Errorf("WaitForUserUpdate(%v): %v, want nil", m, err)
				}
			}
		})
	}
}

// TestUpdateValidation verifies the correctness of updates submitted by the client.
func TestUpdateValidation(ctx context.Context, env *Env, t *testing.T) {
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
		{false, context.Background(), "alice", []byte("alice-key1"), signers, authorizedKeys},
		{false, authentication.WithOutgoingFakeAuth(ctx, "carol"), "bob", []byte("bob-key1"), signers, authorizedKeys},
		{true, authentication.WithOutgoingFakeAuth(ctx, "dave"), "dave", []byte("dave-key1"), signers, authorizedKeys},
		{true, authentication.WithOutgoingFakeAuth(ctx, "eve"), "eve", []byte("eve-key1"), signers, authorizedKeys},
	} {
		u := &tpb.User{
			DomainId:       env.Domain.DomainId,
			AppId:          appID,
			UserId:         tc.userID,
			PublicKeyData:  tc.profile,
			AuthorizedKeys: tc.authorizedKeys,
		}
		cctx, cancel := context.WithTimeout(tc.ctx, env.Timeout)
		defer cancel()
		m, err := env.Client.Update(cctx, u, tc.signers)

		if tc.want {
			// The first update response is always a retry.
			if got, want := err, context.DeadlineExceeded; got != want {
				t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			env.Receiver.Flush(tc.ctx)
			if _, err := env.Client.WaitForUserUpdate(tc.ctx, m); err != nil {
				t.Errorf("WaitForUserUpdate(): %v, want nil", err)
			}
		} else {
			if got, want := err, context.DeadlineExceeded; got == want {
				t.Fatalf("Update(%v): %v, don't want %v", tc.userID, got, want)
			}
		}
	}
}

// TestListHistory verifies that repeated history values get collapsed properly.
func TestListHistory(ctx context.Context, env *Env, t *testing.T) {
	userID := "bob"
	ctx = authentication.WithOutgoingFakeAuth(ctx, userID)

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
		{0, 1, [][]byte{}, false},                                                        // no profile yet
		{1, 2, [][]byte{cp(1)}, false},                                                   // single profile (first entry at 3)
		{2, 2, [][]byte{cp(1)}, false},                                                   // single profile (first entry at 3)
		{3, 3, [][]byte{cp(2)}, false},                                                   // single (changed) profile
		{4, 4, [][]byte{cp(2)}, false},                                                   // single (unchanged) profile
		{5, 5, [][]byte{cp(2)}, false},                                                   // single (unchanged) profile
		{6, 6, [][]byte{cp(3)}, false},                                                   // single (changed) profile
		{2, 3, [][]byte{cp(1), cp(2)}, false},                                            // multiple profiles
		{0, 3, [][]byte{cp(1), cp(2)}, false},                                            // test 'nil' first profile(s)
		{2, 9, [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5)}, false},                       // filtering
		{8, 15, [][]byte{cp(4), cp(5), cp(6)}, false},                                    // filtering consecutive resubmitted profiles
		{8, 18, [][]byte{cp(4), cp(5), cp(6), cp(5), cp(7)}, false},                      // no filtering of resubmitted profiles
		{0, 18, [][]byte{cp(1), cp(2), cp(3), cp(4), cp(5), cp(6), cp(5), cp(7)}, false}, // multiple pages
		{0, 1000, [][]byte{}, true},                                                      // Invalid end epoch, beyond current epoch
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

func (env *Env) setupHistory(ctx context.Context, domain *pb.Domain, userID string, signers []signatures.Signer, authorizedKeys []*keyspb.PublicKey) error {
	// Setup. Each profile entry is either nil, to indicate that the user
	// did not submit a new profile in that epoch, or contains the profile
	// that the user is submitting. The user profile history contains the
	// following profiles:
	// Profile Value: err nil 1  2  2  2  3  3  4  5  5 5 5 5 5 6 6 5 7 7
	// Map Revision:  1  2  3  4  5  6  7  8  9  10 ...
	// Log Max Index: 1  2  3  4  5  6  7  8  9  10 ...
	// Log TreeSize:  2  3  4  5  6  7  8  9  10 11 ...
	// Note that profile 5 is submitted twice by the user to test that
	// filtering case.
	for i, p := range [][]byte{
		nil, cp(1), cp(2), nil, nil, cp(3), nil,
		cp(4), cp(5), cp(5), nil, nil, nil, nil, cp(6),
		nil, cp(5), cp(7), nil,
	} {
		if p != nil {
			u := &tpb.User{
				DomainId:       domain.DomainId,
				AppId:          appID,
				UserId:         userID,
				PublicKeyData:  p,
				AuthorizedKeys: authorizedKeys,
			}
			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()
			// The first update response is always a retry.
			m, err := env.Client.Update(cctx, u, signers)
			if err != context.DeadlineExceeded {
				return fmt.Errorf("Update(%v, %v): %v, want %v", userID, i, err, context.DeadlineExceeded)
			}
			cctx, cancel = context.WithTimeout(ctx, env.Timeout)
			defer cancel()
			env.Receiver.Flush(cctx)
			cctx, cancel = context.WithTimeout(ctx, env.Timeout)
			defer cancel()
			if _, err := env.Client.WaitForUserUpdate(cctx, m); err != nil {
				return fmt.Errorf("WaitForUserUpdate(%v): %v, want nil", m, err)
			}
		} else {
			// Create an empty epoch.
			env.Receiver.Flush(ctx)
		}
	}
	return nil
}

func sortHistory(history map[*types.MapRootV1][]byte) [][]byte {
	keys := make([]*types.MapRootV1, 0, len(history))
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
type mapHeads []*types.MapRootV1

func (m mapHeads) Len() int           { return len(m) }
func (m mapHeads) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m mapHeads) Less(i, j int) bool { return m[i].Revision < m[j].Revision }

// cp creates a dummy profile using the passed tag.
func cp(tag int) []byte {
	return []byte(fmt.Sprintf("bar%v", tag))
}

// TODO: Test AppID filtering when implemented.
