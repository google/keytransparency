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
	"encoding/pem"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"

	"golang.org/x/net/context"

	ctmap "github.com/google/keytransparency/core/proto/ctmap"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
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
	primaryKeys = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func createSigner(t *testing.T, privKey string) signatures.Signer {
	signatures.Rand = DevZero{}
	signer, err := factory.NewSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Fatalf("factory.NewSigner failed: %v", err)
	}
	return signer
}

func getAuthorizedKey(pubKey string) *tpb.PublicKey {
	pk, _ := pem.Decode([]byte(pubKey))
	return &tpb.PublicKey{
		KeyType: &tpb.PublicKey_EcdsaVerifyingP256{
			EcdsaVerifyingP256: pk.Bytes,
		},
	}
}

func TestEmptyGetAndUpdate(t *testing.T) {
	bctx := context.Background()
	auth := authentication.NewFake()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	// Create lists of signers.
	signer1 := createSigner(t, testPrivKey1)
	signer2 := createSigner(t, testPrivKey2)
	signers1 := []signatures.Signer{signer1}
	signers2 := []signatures.Signer{signer1, signer2}
	signers3 := []signatures.Signer{signer2}

	// Create lists of authorized keys
	authorizedKey1 := getAuthorizedKey(testPubKey1)
	authorizedKey2 := getAuthorizedKey(testPubKey2)
	authorizedKeys1 := []*tpb.PublicKey{authorizedKey1}
	authorizedKeys2 := []*tpb.PublicKey{authorizedKey1, authorizedKey2}
	authorizedKeys3 := []*tpb.PublicKey{authorizedKey2}

	for _, tc := range []struct {
		want           bool
		insert         bool
		ctx            context.Context
		userID         string
		signers        []signatures.Signer
		authorizedKeys []*tpb.PublicKey
	}{
		{false, false, context.Background(), "noalice", signers1, authorizedKeys1}, // Empty
		{false, true, auth.NewContext("bob"), "bob", signers1, authorizedKeys1},    // Insert
		{false, false, context.Background(), "nocarol", signers1, authorizedKeys1}, // Empty
		{true, false, context.Background(), "bob", signers1, authorizedKeys1},      // Not Empty
		{true, true, auth.NewContext("bob"), "bob", signers1, authorizedKeys1},     // Update
		{true, true, auth.NewContext("bob"), "bob", signers2, authorizedKeys2},     // Update, changing keys
		{true, true, auth.NewContext("bob"), "bob", signers3, authorizedKeys3},     // Update, using new keys
	} {
		// Check profile.
		if err := env.checkProfile(tc.userID, tc.want); err != nil {
			t.Errorf("checkProfile(%v, %v) failed: %v", tc.userID, tc.want, err)
		}
		// Update profile.
		if tc.insert {
			req, err := env.Client.Update(tc.ctx, tc.userID, &tpb.Profile{Keys: primaryKeys}, tc.signers, tc.authorizedKeys)
			if got, want := err, grpcc.ErrRetry; got != want {
				t.Fatalf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			if err := env.Signer.CreateEpoch(bctx); err != nil {
				t.Errorf("CreateEpoch(_): %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

// checkProfile ensures that the returned profile is as expected along with the
// keys it carries.
func (e *Env) checkProfile(userID string, want bool) error {
	profile, _, err := e.Client.GetEntry(context.Background(), userID)
	if err != nil {
		return fmt.Errorf("GetEntry(%v): %v, want nil", userID, err)
	}
	if got := profile != nil; got != want {
		return fmt.Errorf("GetEntry(%v): %v, want %v", userID, profile, want)
	}
	if want {
		if got, want := len(profile.GetKeys()), 1; got != want {
			return fmt.Errorf("len(GetKeys()) = %v, want; %v", got, want)
		}
		if got, want := profile.GetKeys(), primaryKeys; !reflect.DeepEqual(got, want) {
			return fmt.Errorf("GetKeys() = %v, want: %v", got, want)
		}
	}
	return nil
}

func TestUpdateValidation(t *testing.T) {
	bctx := context.Background()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	auth := authentication.NewFake()
	profile := &tpb.Profile{
		Keys: map[string][]byte{
			"foo": []byte("bar"),
		},
	}

	// Create lists of signers and authorized keys
	signers := []signatures.Signer{createSigner(t, testPrivKey1)}
	authorizedKeys := []*tpb.PublicKey{getAuthorizedKey(testPubKey1)}

	for _, tc := range []struct {
		want           bool
		ctx            context.Context
		userID         string
		profile        *tpb.Profile
		signers        []signatures.Signer
		authorizedKeys []*tpb.PublicKey
	}{
		{false, context.Background(), "alice", profile, signers, authorizedKeys},
		{false, auth.NewContext("carol"), "bob", profile, signers, authorizedKeys},
		{true, auth.NewContext("dave"), "dave", profile, signers, authorizedKeys},
		{true, auth.NewContext("eve"), "eve", profile, signers, authorizedKeys},
	} {
		req, err := env.Client.Update(tc.ctx, tc.userID, tc.profile, tc.signers, tc.authorizedKeys)

		// The first update response is always a retry.
		if got, want := err, grpcc.ErrRetry; (got == want) != tc.want {
			t.Fatalf("Update(%v): %v != %v, want %v", tc.userID, err, want, tc.want)
		}
		if tc.want {
			if err := env.Signer.CreateEpoch(bctx); err != nil {
				t.Errorf("CreateEpoch(_): %v", err)
			}
			if err := env.Client.Retry(tc.ctx, req); err != nil {
				t.Errorf("Retry(%v): %v, want nil", req, err)
			}
		}
	}
}

func TestListHistory(t *testing.T) {
	userID := "bob"
	ctx := authentication.NewFake().NewContext(userID)

	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	// Create lists of signers and authorized keys
	signers := []signatures.Signer{createSigner(t, testPrivKey1)}
	authorizedKeys := []*tpb.PublicKey{getAuthorizedKey(testPubKey1)}

	if err := env.setupHistory(ctx, userID, signers, authorizedKeys); err != nil {
		t.Fatalf("setupHistory failed: %v", err)
	}

	for _, tc := range []struct {
		start, end  int64
		wantHistory []*tpb.Profile
		wantErr     bool
	}{
		{0, 3, []*tpb.Profile{cp(1)}, false},                                                   // zero start epoch
		{3, 3, []*tpb.Profile{cp(1)}, false},                                                   // single profile
		{3, 4, []*tpb.Profile{cp(1), cp(2)}, false},                                            // multiple profiles
		{1, 4, []*tpb.Profile{cp(1), cp(2)}, false},                                            // test 'nil' first profile(s)
		{3, 10, []*tpb.Profile{cp(1), cp(2), cp(3), cp(4), cp(5)}, false},                      // filtering
		{9, 16, []*tpb.Profile{cp(4), cp(5), cp(6)}, false},                                    // filtering consecutive resubmitted profiles
		{9, 19, []*tpb.Profile{cp(4), cp(5), cp(6), cp(5), cp(7)}, false},                      // no filtering of resubmitted profiles
		{1, 19, []*tpb.Profile{cp(1), cp(2), cp(3), cp(4), cp(5), cp(6), cp(5), cp(7)}, false}, // multiple pages
		{1, 1000, []*tpb.Profile{}, true},                                                      // Invalid end epoch, beyond current epoch
	} {
		resp, err := env.Client.ListHistory(ctx, userID, tc.start, tc.end)
		if got := err != nil; got != tc.wantErr {
			t.Errorf("ListHistory(%v, %v) failed: %v, wantErr :%v", tc.start, tc.end, err, tc.wantErr)
		}
		if err != nil {
			continue
		}

		if got := sortHistory(resp); !reflect.DeepEqual(got, tc.wantHistory) {
			t.Errorf("ListHistory(%v, %v): \n%v, want \n%v", tc.start, tc.end, got, tc.wantHistory)
		}
	}
}

func (e *Env) setupHistory(ctx context.Context, userID string, signers []signatures.Signer, authorizedKeys []*tpb.PublicKey) error {
	// Setup. Each profile entry is either nil, to indicate that the user
	// did not submit a new profile in that epoch, or contains the profile
	// that the user is submitting. The user profile history contains the
	// following profiles:
	// [nil, nil, 1, 2, 2, 2, 3, 3, 4, 5, 5, 5, 5, 5, 5, 6, 6, 5, 7, 7].  // Note that profile 5 is submitted twice by the user to test that
	// filtering case.
	for i, p := range []*tpb.Profile{
		nil, nil, cp(1), cp(2), nil, nil, cp(3), nil,
		cp(4), cp(5), cp(5), nil, nil, nil, nil, cp(6),
		nil, cp(5), cp(7), nil,
	} {
		if p != nil {
			_, err := e.Client.Update(ctx, userID, p, signers, authorizedKeys)
			// The first update response is always a retry.
			if got, want := err, grpcc.ErrRetry; got != want {
				return fmt.Errorf("Update(%v, %v)=(_, %v), want (_, %v)", userID, i, got, want)
			}
		}
		if err := e.Signer.CreateEpoch(ctx); err != nil {
			return fmt.Errorf("CreateEpoch(_): %v", err)
		}
	}
	return nil
}

func sortHistory(history map[*ctmap.MapHead]*tpb.Profile) []*tpb.Profile {
	keys := make([]*ctmap.MapHead, 0, len(history))
	for k := range history {
		keys = append(keys, k)
	}
	sort.Sort(mapHeads(keys))
	profiles := make([]*tpb.Profile, len(keys))
	for i, k := range keys {
		profiles[i] = history[k]
	}
	return profiles
}

// MapHead sorter.
type mapHeads []*ctmap.MapHead

func (m mapHeads) Len() int           { return len(m) }
func (m mapHeads) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m mapHeads) Less(i, j int) bool { return m[i].Epoch < m[j].Epoch }

// cp creates a dummy profile using the passed tag.
func cp(tag int) *tpb.Profile {
	return &tpb.Profile{
		Keys: map[string][]byte{
			fmt.Sprintf("foo%v", tag): []byte(fmt.Sprintf("bar%v", tag)),
		},
	}
}

// TODO: Test AppID filtering when implemented.
