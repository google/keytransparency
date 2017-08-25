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

	"github.com/google/keytransparency/core/monitor"
	"github.com/google/keytransparency/core/monitor/storage"
	kpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/keytransparency/impl/monitor/client"
	spb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
	mupb "github.com/google/keytransparency/impl/proto/mutation_v1_service"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"

	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
)

const (
	monitorPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAV7H3qRi/cj/w04vEQBFjLdhcXRbZR4ouT5zaAy1XUHoAoGCCqGSM49
AwEHoUQDQgAEqUDbATN2maGIm6YQLpjx67bYN1hxPPdF0VrPTZe36yQhH+GCwZQV
amFdON6OhjYnBmJWe4fVnbxny0PfpkvXtg==
-----END EC PRIVATE KEY-----`
)

func TestMonitorEmptyStart(t *testing.T) {
	bctx := context.Background()
	env := NewEnv(t)
	defer env.Close(t)
	env.Client.RetryCount = 0

	// setup monitor:

	// TODO(ismail) setup a proper log environment in the integration
	// environment, then use GetDomainInfo here:
	c := spb.NewKeyTransparencyServiceClient(env.Conn)
	resp, err := c.GetDomainInfo(bctx, &kpb.GetDomainInfoRequest{})
	if err != nil {
		t.Fatalf("Couldn't retrieve domain info: %v", err)
	}
	signer, err := pem.UnmarshalPrivateKey(monitorPrivKey, "")
	if err != nil {
		t.Fatalf("Couldn't create signer: %v", err)
	}
	//logTree := resp.Log
	mapTree := resp.Map
	store := storage.New()
	mon, err := monitor.New(fake.NewFakeTrillianLogVerifier(), mapTree, crypto.NewSHA256Signer(signer), store)
	if err != nil {
		t.Fatalf("Couldn't create monitor: %v", err)
	}
	// Initialization and CreateEpoch is called by NewEnv
	mcc := mupb.NewMutationServiceClient(env.Conn)
	mutCli := client.New(mcc, time.Second)
	//  verify first SMR
	mutResp, err := mutCli.PollMutations(bctx, 1)
	if err != nil {
		t.Fatalf("Could not query mutations: %v", err)
	}
	if err := mon.Process(mutResp); err != nil {
		t.Fatalf("Monitor could process mutations: %v", err)
	}
	mresp, err := store.Get(1)
	if err != nil {
		t.Fatalf("Could not read monitoring response: %v", err)
	}
	for _, err := range mresp.Errors {
		t.Errorf("Got error: %v", err)
	}

	// client sends one mutation, sequencer "signs", monitor verifies
	userID := "test@test.com"
	signers := []signatures.Signer{createSigner(t, testPrivKey1)}
	authorizedKeys := []*kpb.PublicKey{getAuthorizedKey(testPubKey1)}

	_, err = env.Client.Update(GetNewOutgoingContextWithFakeAuth("test@test.com"), userID, appID, []byte("testProfile"), signers, authorizedKeys)
	if err != grpcc.ErrRetry {
		t.Fatalf("Could not send update request: %v", err)
	}
	if err := env.Signer.CreateEpoch(bctx, false); err != nil {
		t.Errorf("CreateEpoch(_): %v", err)
	}
	mutResp, err = mutCli.PollMutations(bctx, 2)
	if err != nil {
		t.Fatalf("Could not query mutations: %v", err)
	}
	if err := mon.Process(mutResp); err != nil {
		t.Fatalf("Monitor could not process mutations: %v", err)
	}
	mresp, err = store.Get(2)
	if err != nil {
		t.Fatalf("Could not read monitoring response: %v", err)
	}
	for _, err := range mresp.Errors {
		t.Errorf("Got error: %v", err)
	}
}
