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
	"crypto"
	"sync"
	"testing"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/monitor"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tcrypto "github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/pem"

	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
)

const (
	monitorPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIAV7H3qRi/cj/w04vEQBFjLdhcXRbZR4ouT5zaAy1XUHoAoGCCqGSM49
AwEHoUQDQgAEqUDbATN2maGIm6YQLpjx67bYN1hxPPdF0VrPTZe36yQhH+GCwZQV
amFdON6OhjYnBmJWe4fVnbxny0PfpkvXtg==
-----END EC PRIVATE KEY-----`
)

// TestMonitor verifies that the monitor correctly verifies transitions between revisions.
func TestMonitor(ctx context.Context, env *Env, t *testing.T) []*tpb.Action {
	// setup monitor:
	privKey, err := pem.UnmarshalPrivateKey(monitorPrivKey, "")
	if err != nil {
		t.Fatalf("Couldn't create signer: %v", err)
	}
	signer := tcrypto.NewSigner(0, privKey, crypto.SHA256)
	store := fake.NewMonitorStorage()
	mon, err := monitor.NewFromDirectory(env.Cli, env.Directory, signer, store)
	if err != nil {
		t.Fatalf("Couldn't create monitor: %v", err)
	}

	// Setup a bunch of revisions with data to verify.
	for _, e := range []struct {
		revision    int64
		signers     []tink.Signer
		userUpdates []*client.User
	}{
		{
			revision: 1,
		},
		{
			revision: 2,
			signers:  testutil.SignKeysetsFromPEMs(testPrivKey1),
			userUpdates: []*client.User{
				{
					UserID:         "alice@test.com",
					PublicKeyData:  []byte("alice-key1"),
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
				},
			},
		},
		{
			revision: 3,
			signers:  testutil.SignKeysetsFromPEMs(testPrivKey1),
			userUpdates: []*client.User{
				{
					UserID:         "bob@test.com",
					PublicKeyData:  []byte("bob-key1"),
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
				},
				{
					UserID:         "carol@test.com",
					PublicKeyData:  []byte("carol-key1"),
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
				},
			},
		},
	} {
		for _, u := range e.userUpdates {
			cctx, cancel := context.WithTimeout(ctx, env.Timeout)
			defer cancel()
			m, err := env.Client.CreateMutation(cctx, u)
			if err != nil {
				t.Fatalf("CreateMutation(%v): %v", u.UserID, err)
			}
			if err := env.Client.QueueMutation(ctx, m, e.signers,
				env.CallOpts(u.UserID)...); err != nil {
				t.Errorf("QueueMutation(): %v", err)
			}
		}

		err := runBatchAndPublish(ctx, env, int32(len(e.userUpdates)), int32(len(e.userUpdates))*2, false)
		if err != nil {
			t.Errorf("runBatchAndPublish(): %v", err)
		}
	}

	cctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err = mon.ProcessLoop(cctx, 0)
	}()
	time.Sleep(env.Timeout)
	cancel()
	wg.Wait()
	if err != context.Canceled && status.Code(err) != codes.Canceled {
		t.Errorf("Monitor could not process mutations: %v", err)
	}

	for i := int64(1); i < 4; i++ {
		mresp, err := store.Get(i)
		if err != nil {
			t.Errorf("Could not read monitoring response for revision %v: %v", i, err)
			continue
		}
		for _, err := range mresp.Errors {
			t.Errorf("Got error: %v", err)
		}
	}
	return nil
}
