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

package entry

import (
	"testing"

	"github.com/google/trillian/crypto/keyspb"

	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
)

const domainID = "default"

func TestReplaceAuthorizedKeys(t *testing.T) {
	for _, tc := range []struct {
		pubKeys []*keyspb.PublicKey
		wantErr bool
	}{
		{pubKeys: nil, wantErr: true},
		{pubKeys: []*keyspb.PublicKey{{}}, wantErr: false},
	} {
		index := []byte("index")
		userID := "bob"
		appID := "app1"
		m := NewMutation(index, domainID, appID, userID)
		err := m.ReplaceAuthorizedKeys(tc.pubKeys)
		if got, want := err != nil, tc.wantErr; got != want {
			t.Errorf("ReplaceAuthorizedKeys(%v): %v, wantErr: %v", tc.pubKeys, got, want)
		}
	}
}

func TestCreateAndVerify(t *testing.T) {
	for _, tc := range []struct {
		old     []byte
		pubKeys []*keyspb.PublicKey
		signers []signatures.Signer
		data    []byte
	}{
		{
			old:     nil,
			pubKeys: mustPublicKeys([]string{testPubKey1}),
			signers: []signatures.Signer{createSigner(t, testPrivKey1)},
			data:    []byte("foo"),
		},
	} {
		index := []byte{}
		userID := "alice"
		appID := "app1"

		m := NewMutation(index, domainID, appID, userID)
		if err := m.SetPrevious(tc.old); err != nil {
			t.Errorf("NewMutation(%v): %v", tc.old, err)
			continue
		}
		if err := m.SetCommitment(tc.data); err != nil {
			t.Errorf("SetCommitment(%v): %v", tc.data, err)
			continue
		}
		if err := m.ReplaceAuthorizedKeys(tc.pubKeys); err != nil {
			t.Errorf("ReplaceAuthorizedKeys(%v): %v", tc.pubKeys, err)
			continue
		}
		update, err := m.SerializeAndSign(tc.signers, 0)
		if err != nil {
			t.Errorf("SerializeAndSign(%v): %v", tc.signers, err)
			continue
		}
		// Verify mutation.
		oldValue, err := FromLeafValue(tc.old)
		if err != nil {
			t.Errorf("FromLeafValue(%v): %v", tc.old, err)
			continue
		}
		f := New()
		newEntry, err := f.Mutate(oldValue, update.GetEntryUpdate().GetMutation())
		if err != nil {
			t.Errorf("Mutate(%v): %v", update.GetEntryUpdate().GetMutation(), err)
			continue
		}

		newLeaf, err := ToLeafValue(newEntry)
		if err != nil {
			t.Errorf("ToLeafValue(): %v", err)
			continue
		}
		if err := m.Check(newLeaf); err != nil {
			t.Errorf("Check(): %v", err)
		}
	}
}

func createSigner(t *testing.T, privKey string) signatures.Signer {
	signatures.Rand = dev.Zeros
	signer, err := factory.NewSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Fatalf("factory.NewSigner failed: %v", err)
	}
	return signer
}
