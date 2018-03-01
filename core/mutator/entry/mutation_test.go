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

	"github.com/google/keytransparency/core/testutil"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
)

const domainID = "default"

func TestCreateAndVerify(t *testing.T) {
	signature.PublicKeyVerifyConfig().RegisterStandardKeyTypes()
	signature.PublicKeySignConfig().RegisterStandardKeyTypes()
	for _, tc := range []struct {
		old     []byte
		pubKeys *tink.KeysetHandle
		signers []*tink.KeysetHandle
		data    []byte
	}{
		{
			old:     nil,
			pubKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1),
			data:    []byte("foo"),
		},
	} {
		index := []byte{}
		userID := "alice"
		appID := "app1"

		m := NewMutation(index, domainID, appID, userID)
		if err := m.SetPrevious(tc.old, true); err != nil {
			t.Errorf("NewMutation(%v): %v", tc.old, err)
			continue
		}
		if err := m.SetCommitment(tc.data); err != nil {
			t.Errorf("SetCommitment(%v): %v", tc.data, err)
			continue
		}
		if err := m.ReplaceAuthorizedKeys(tc.pubKeys.Keyset()); err != nil {
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

		if !m.EqualsRequested(newEntry) {
			t.Errorf("EqualsRequested(): false")
		}
	}
}
