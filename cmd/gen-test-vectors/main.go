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
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/jsonpb"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/keytransparency/impl/integration"
	"github.com/google/martian/log"
	"github.com/google/tink/go/tink"
	"github.com/google/trillian/types"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
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
)

func main() {
	flag.Parse()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	env, err := integration.NewEnv(ctx)
	if err != nil {
		glog.Fatalf("Could not create Env: %v", err)
	}
	defer env.Close()
	cctx, cancel2 := context.WithCancel(ctx)
	if err := GenerateTestVectors(cctx, env); err != nil {
		glog.Fatalf("GenerateTestVectors(): %v", err)
	}
	cancel2()
}

// GenerateTestVectors verifies set/get semantics.
// TODO(gbelvin): Migrate into core/integration/client_tests to avoid code rot.
func GenerateTestVectors(ctx context.Context, env *integration.Env) error {
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		if err := sequencer.PeriodicallyRun(ctx, ticker.C,
			func(ctx context.Context) error {
				_, err := env.Sequencer.RunBatch(ctx, &spb.RunBatchRequest{
					DirectoryId: env.Directory.DirectoryId,
					MinBatch:    1,
					MaxBatch:    100,
				})
				return err
			}); err != nil {
			log.Errorf("PeriodicallyRun(): %v", err)
		}
	}()
	// Create lists of signers.
	signers1 := testutil.SignKeysetsFromPEMs(testPrivKey1)

	// Create lists of authorized keys
	authorizedKeys1 := testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset()

	// Collect a list of valid GetUserResponses
	getUserResps := make([]testdata.GetUserResponseVector, 0)

	// Start with an empty trusted log root
	slr := &types.LogRootV1{}

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
		e, err := env.Cli.GetUser(ctx, &pb.GetUserRequest{
			DirectoryId:          env.Directory.DirectoryId,
			UserId:               tc.userID,
			LastVerifiedTreeSize: int64(slr.TreeSize),
		})
		if err != nil {
			return fmt.Errorf("gen-test-vectors: GetUser(): %v", err)
		}
		_, newslr, err := env.Client.VerifyGetUserResponse(ctx, env.Directory.DirectoryId, tc.userID, *slr, e)
		if err != nil {
			return fmt.Errorf("gen-test-vectors: VerifyGetUserResponse(): %v", err)
		}

		if got, want := e.GetLeaf().GetCommitted().GetData(), tc.wantProfile; !bytes.Equal(got, want) {
			return fmt.Errorf("gen-test-vectors: VerifiedGetUser(%v): %s, want %s", tc.userID, got, want)
		}

		// Update the trusted root on the first revision, then let it fall behind
		// every few revisions to make consistency proofs more interesting.
		trust := newslr.TreeSize%5 == 1
		if trust {
			slr = newslr
		}
		getUserResps = append(getUserResps, testdata.GetUserResponseVector{
			Desc:        tc.desc,
			UserID:      tc.userID,
			Resp:        e,
			TrustNewLog: trust,
		})

		// Update profile.
		if tc.setProfile != nil {
			u := &tpb.User{
				DirectoryId:    env.Directory.DirectoryId,
				UserId:         tc.userID,
				PublicKeyData:  tc.setProfile,
				AuthorizedKeys: tc.authorizedKeys,
			}
			cctx, cancel := context.WithTimeout(tc.ctx, env.Timeout)
			defer cancel()
			_, err := env.Client.Update(cctx, u, tc.signers)
			if err != nil {
				return fmt.Errorf("gen-test-vectors: Update(%v): %v", tc.userID, err)
			}
		}
	}

	if err := SaveTestVectors(*testdataDir, env, getUserResps); err != nil {
		return fmt.Errorf("gen-test-vectors: SaveTestVectors(): %v", err)
	}
	return nil
}

// SaveTestVectors generates test vectors for interoprability testing.
func SaveTestVectors(dir string, env *integration.Env, resps []testdata.GetUserResponseVector) error {
	marshaler := &jsonpb.Marshaler{
		Indent: "\t",
	}
	// Output all key material needed to verify the test vectors.
	directoryFile := dir + "/directory.json"
	f, err := os.Create(directoryFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := marshaler.Marshal(f, env.Directory); err != nil {
		return fmt.Errorf("gen-test-vectors: jsonpb.Marshal(): %v", err)
	}

	// Save list of responses
	respFile := dir + "/getentryresponse.json"
	out, err := json.MarshalIndent(resps, "", "\t")
	if err != nil {
		return fmt.Errorf("gen-test-vectors: json.Marshal(): %v", err)
	}
	if err := ioutil.WriteFile(respFile, out, 0666); err != nil {
		return fmt.Errorf("gen-test-vectors: WriteFile(%v): %v", respFile, err)
	}
	return nil
}
