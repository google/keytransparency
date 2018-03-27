// Copyright 2018 Google Inc. All Rights Reserved.
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

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/types"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	"github.com/google/keytransparency/impl/integration"
)

var (
	testdataDir = flag.String("testdata", "core/testdata", "The directory in which to place the generated test data")
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
	appID = "app"
)

func main() {
	flag.Parse()
	ctx := context.Background()
	signatures.Rand = dev.Zeros // Generate the same signatures every time.

	env, err := integration.NewEnv()
	if err != nil {
		glog.Fatalf("Could not create Env: %v", err)
	}
	defer env.Close()
	GenerateTestVectors(ctx, env)

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

// GenerateTestVectors verifies set/get semantics.
func GenerateTestVectors(ctx context.Context, env *integration.Env) error {
	// Create lists of signers.
	signer1, err := factory.NewSignerFromPEM([]byte(testPrivKey1))
	if err != nil {
		return err
	}
	signers1 := []signatures.Signer{signer1}

	// Create lists of authorized keys
	authorizedKey1 := getAuthorizedKey(testPubKey1)
	authorizedKeys1 := []*keyspb.PublicKey{authorizedKey1}

	// Collect a list of valid GetEntryResponses
	getEntryResps := make([]testdata.GetEntryResponseVector, 0)

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
	} {
		// Check profile.
		e, err := env.Cli.GetEntry(ctx, &pb.GetEntryRequest{
			DomainId: env.Domain.DomainId,
			UserId:   tc.userID,
			AppId:    appID,
		})
		if err != nil {
			return fmt.Errorf("GetEntry(): %v", err)
		}
		if _, _, err := env.Client.VerifyGetEntryResponse(ctx, env.Domain.DomainId, appID, tc.userID, types.LogRootV1{}, e); err != nil {
			return fmt.Errorf("VerifyGetEntryResponse(): %v", err)
		}
		if got, want := e.GetCommitted().GetData(), tc.wantProfile; !bytes.Equal(got, want) {
			return fmt.Errorf("VerifiedGetEntry(%v): %s, want %s", tc.userID, got, want)
		}
		getEntryResps = append(getEntryResps, testdata.GetEntryResponseVector{
			Desc:   tc.desc,
			AppID:  appID,
			UserID: tc.userID,
			Resp:   e,
		})

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
				return fmt.Errorf("Update(%v): %v, want %v", tc.userID, got, want)
			}
			cctx, cancel = context.WithTimeout(tc.ctx, env.Timeout)
			defer cancel()
			env.Receiver.Flush(cctx)
			cctx, cancel = context.WithTimeout(tc.ctx, env.Timeout)
			defer cancel()
			if _, err := env.Client.WaitForUserUpdate(cctx, m); err != nil {
				return fmt.Errorf("WaitForUserUpdate(%v): %v, want nil", m, err)
			}
		}
		if err := SaveTestVectors(env, getEntryResps); err != nil {
			return fmt.Errorf("SaveTestVectors(): %v", err)
		}
	}
	return nil
}

// SaveTestVectors generates test vectors for interoprability testing.
func SaveTestVectors(env *integration.Env, resps []testdata.GetEntryResponseVector) error {
	// Output all key material needed to verify the test vectors.
	domainFile := *testdataDir + "/domain.json"
	b, err := json.Marshal(env.Domain)
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	var out bytes.Buffer
	json.Indent(&out, b, "", "\t")
	if err := ioutil.WriteFile(domainFile, out.Bytes(), 0666); err != nil {
		return fmt.Errorf("WriteFile(%v): %v", domainFile, err)
	}
	out.Reset()

	// Save list of responses
	respFile := *testdataDir + "/getentryresponse.json"
	b, err = json.Marshal(resps)
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	json.Indent(&out, b, "", "\t")
	if err := ioutil.WriteFile(respFile, out.Bytes(), 0666); err != nil {
		return fmt.Errorf("WriteFile(%v): %v", respFile, err)
	}
	return nil
}
