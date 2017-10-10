// Copyright 2017 Google Inc. All Rights Reserved.
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
	"context"
	"testing"
	"time"

	"github.com/google/keytransparency/core/client/grpcc"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/monitor"
	"github.com/google/keytransparency/core/monitor/storage"
	"github.com/google/keytransparency/impl/monitor/client"

	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keyspb"

	spb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	kpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	mupb "github.com/google/keytransparency/core/proto/mutation_v1_grpc"
)

const (
	monitorPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAV7H3qRi/cj/w04vEQBFjLdhcXRbZR4ouT5zaAy1XUHoAoGCCqGSM49
AwEHoUQDQgAEqUDbATN2maGIm6YQLpjx67bYN1hxPPdF0VrPTZe36yQhH+GCwZQV
amFdON6OhjYnBmJWe4fVnbxny0PfpkvXtg==
-----END EC PRIVATE KEY-----`
)

func TestMonitor(t *testing.T) {
	bctx := context.Background()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0
	c := spb.NewKeyTransparencyServiceClient(env.Conn)
	// setup monitor:
	resp, err := c.GetDomainInfo(bctx, &kpb.GetDomainInfoRequest{})
	if err != nil {
		t.Fatalf("Couldn't retrieve domain info: %v", err)
	}
	signer, err := pem.UnmarshalPrivateKey(monitorPrivKey, "")
	if err != nil {
		t.Fatalf("Couldn't create signer: %v", err)
	}
	logTree := resp.Log
	mapTree := resp.Map
	_ = logTree
	store := storage.New()
	// TODO(ismail): setup and use a real logVerifier instead:
	mon, err := monitor.New(fake.NewFakeTrillianLogVerifier(), mapTree, crypto.NewSHA256Signer(signer), store)
	if err != nil {
		t.Fatalf("Couldn't create monitor: %v", err)
	}
	mcc := mupb.NewMutationServiceClient(env.Conn)
	mutCli := client.New(mcc, time.Second)

	for _, tc := range []struct {
		// the userIDs to update, if no userIDs are provided, no update request
		// will be send before querying
		userIDs        []string
		updateData     []byte
		signers        []signatures.Signer
		authorizedKeys []*keyspb.PublicKey
		// the epoch to query after sending potential updates
		queryEpoch int64
	}{
		// query first epoch, don't update
		{[]string{}, nil, nil, nil, 1},
		// create one mutation and new epoch (not forced like in sequencer):
		{[]string{"test@test.com"}, []byte("testData"), []signatures.Signer{createSigner(t, testPrivKey1)}, []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)}, 2},
		// create several mutations and new epoch
		{[]string{"test@test.com", "test2@test2.com"}, []byte("more update data"), []signatures.Signer{createSigner(t, testPrivKey1)}, []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)}, 3},
	} {
		for _, userID := range tc.userIDs {
			_, err = env.Client.Update(GetNewOutgoingContextWithFakeAuth(userID),
				userID, appID, tc.updateData, tc.signers, tc.authorizedKeys)
			if err != grpcc.ErrRetry {
				t.Fatalf("Could not send update request: %v", err)
			}
		}

		if err := env.Signer.CreateEpoch(bctx, false); err != nil {
			t.Fatalf("CreateEpoch(_): %v", err)
		}

		mutResp, err := mutCli.PollMutations(bctx, tc.queryEpoch)
		if err != nil {
			t.Fatalf("Could not query mutations: %v", err)
		}

		if err := mon.Process(mutResp); err != nil {
			t.Fatalf("Monitor could not process mutations: %v", err)
		}

		mresp, err := store.Get(tc.queryEpoch)
		if err != nil {
			t.Fatalf("Could not read monitoring response: %v", err)
		}

		for _, err := range mresp.Errors {
			t.Errorf("Got error: %v", err)
		}
	}
}
