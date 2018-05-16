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
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/keytransparency/impl/integration"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
	"github.com/google/trillian/types"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
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

	env, err := integration.NewEnv()
	if err != nil {
		glog.Fatalf("Could not create Env: %v", err)
	}
	defer env.Close()
	if err := GenerateTestVectors(ctx, env); err != nil {
		glog.Fatalf("GenerateTestVectors(): %v", err)
	}
}

// GenerateTestVectors verifies set/get semantics.
func GenerateTestVectors(ctx context.Context, env *integration.Env) error {
	signature.RegisterStandardKeyTypes()
	// Create lists of signers.
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)

	// Create lists of authorized keys
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	// Collect a list of valid GetEntryResponses
	getEntryResps := make([]testdata.GetEntryResponseVector, 0)

	for _, tc := range []struct {
		desc           string
		wantProfile    []byte
		setProfile     []byte
		ctx            context.Context
		userID         string
		signers        []*tink.KeysetHandle
		authorizedKeys *tinkpb.Keyset
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
		if err := SaveTestVectors(*testdataDir, env, getEntryResps); err != nil {
			return fmt.Errorf("SaveTestVectors(): %v", err)
		}
	}
	return nil
}

// SaveTestVectors generates test vectors for interoprability testing.
func SaveTestVectors(dir string, env *integration.Env, resps []testdata.GetEntryResponseVector) error {
	marshaler := &jsonpb.Marshaler{
		Indent: "\t",
	}
	// Output all key material needed to verify the test vectors.
	domainFile := dir + "/domain.json"
	f, err := os.Create(domainFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := marshaler.Marshal(f, env.Domain); err != nil {
		return fmt.Errorf("jsonpb.Marshal(): %v", err)
	}

	// Save list of responses
	respFile := dir + "/getentryresponse.json"
	out, err := json.MarshalIndent(resps, "", "\t")
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	if err := ioutil.WriteFile(respFile, out, 0666); err != nil {
		return fmt.Errorf("WriteFile(%v): %v", respFile, err)
	}
	return nil
}
