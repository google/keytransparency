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

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/monitor"

	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/merkle/hashers"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

const (
	monitorPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAV7H3qRi/cj/w04vEQBFjLdhcXRbZR4ouT5zaAy1XUHoAoGCCqGSM49
AwEHoUQDQgAEqUDbATN2maGIm6YQLpjx67bYN1hxPPdF0VrPTZe36yQhH+GCwZQV
amFdON6OhjYnBmJWe4fVnbxny0PfpkvXtg==
-----END EC PRIVATE KEY-----`
)

// TestMonitor verifies that the monitor correctly verifies transitions between epochs.
func TestMonitor(ctx context.Context, env *Env, t *testing.T) {
	// setup monitor:
	resp, err := env.Cli.GetDomain(ctx, &pb.GetDomainRequest{DomainId: env.Domain.DomainId})
	if err != nil {
		t.Fatalf("Couldn't retrieve domain info: %v", err)
	}
	signer, err := pem.UnmarshalPrivateKey(monitorPrivKey, "")
	if err != nil {
		t.Fatalf("Couldn't create signer: %v", err)
	}
	mapTree := resp.GetMap()
	mapHasher, err := hashers.NewMapHasher(mapTree.GetHashStrategy())
	if err != nil {
		t.Fatalf("Failed creating MapHasher: %v", err)
	}
	mapPubKey, err := der.UnmarshalPublicKey(mapTree.GetPublicKey().GetDer())
	if err != nil {
		t.Fatalf("Could not unmarshal map public key: %v", err)
	}
	store := fake.NewMonitorStorage()
	// TODO(ismail): setup and use a real logVerifier instead:
	mon, err := monitor.New(env.Cli, fake.NewTrillianLogVerifier(),
		mapTree.TreeId, mapHasher, mapPubKey,
		crypto.NewSHA256Signer(signer), store)
	if err != nil {
		t.Fatalf("Couldn't create monitor: %v", err)
	}

	for _, tc := range []struct {
		desc string
		// the userIDs to update, if no userIDs are provided, no update request
		// will be send before querying
		userIDs        []string
		updateData     []byte
		signers        []signatures.Signer
		authorizedKeys []*keyspb.PublicKey
		// the epoch to query after sending potential updates
		queryEpoch int64
	}{
		{
			desc:       "Query first epoch",
			queryEpoch: 1,
		},
		{
			desc:           "create one mutation and new epoch (not forced like in sequencer)",
			userIDs:        []string{"test@test.com"},
			updateData:     []byte("testData"),
			signers:        []signatures.Signer{createSigner(t, testPrivKey1)},
			authorizedKeys: []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)},
			queryEpoch:     3,
		},
		{
			desc:           "create several mutations and new epoch",
			userIDs:        []string{"test@test.com", "test2@test2.com"},
			updateData:     []byte("more update data"),
			signers:        []signatures.Signer{createSigner(t, testPrivKey1)},
			authorizedKeys: []*keyspb.PublicKey{getAuthorizedKey(testPubKey1)},
			queryEpoch:     4,
		},
	} {
		for _, userID := range tc.userIDs {
			u := &tpb.User{
				DomainId:       env.Domain.DomainId,
				AppId:          appID,
				UserId:         userID,
				PublicKeyData:  tc.updateData,
				AuthorizedKeys: tc.authorizedKeys,
			}
			actx := WithOutgoingFakeAuth(ctx, userID)
			cctx, cancel := context.WithTimeout(actx, 500*time.Millisecond)
			defer cancel()
			if _, err = env.Client.Update(cctx, u, tc.signers); err != context.DeadlineExceeded {
				t.Fatalf("Could not send update request: %v", err)
			}
		}

		env.Receiver.Flush(ctx)
		if err := env.Client.WaitForRevision(ctx, tc.queryEpoch); err != nil {
			t.Fatalf("WaitForRevision(): %v", err)
		}

		domainID := env.Domain.DomainId
		cctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		if err := mon.ProcessLoop(cctx, domainID, tc.queryEpoch-1, 40*time.Millisecond); err != context.DeadlineExceeded {
			t.Errorf("Monitor could not process mutations: %v", err)
		}
		cancel()

		mresp, err := store.Get(tc.queryEpoch)
		if err != nil {
			t.Errorf("Could not read monitoring response: %v", err)
			continue
		}
		for _, err := range mresp.Errors {
			t.Errorf("Got error: %v", err)
		}
	}
}
