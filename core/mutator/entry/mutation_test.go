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
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const directoryID = "default"

func TestSerializeAndSign(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		old     []byte
		pubKeys *tink.KeysetHandle
		signers []*tink.KeysetHandle
		data    []byte
		want    codes.Code
	}{
		{
			old:     nil,
			pubKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1),
			data:    []byte("foo"),
		},
		{
			old:     nil,
			pubKeys: testutil.VerifyKeysetFromPEMs(testPubKey1),
			signers: testutil.SignKeysetsFromPEMs(testPrivKey2),
			data:    []byte("foo"),
			want:    codes.PermissionDenied,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			index := []byte{}
			userID := "alice"
			appID := "app1"

			m := NewMutation(index, directoryID, appID, userID)
			if err := m.SetPrevious(tc.old, true); err != nil {
				t.Fatalf("NewMutation(%v): %v", tc.old, err)
			}
			if err := m.SetCommitment(tc.data); err != nil {
				t.Fatalf("SetCommitment(%v): %v", tc.data, err)
			}
			if err := m.ReplaceAuthorizedKeys(tc.pubKeys.Keyset()); err != nil {
				t.Fatalf("ReplaceAuthorizedKeys(%v): %v", tc.pubKeys, err)
			}
			_, err := m.SerializeAndSign(tc.signers)
			if got := status.Code(err); got != tc.want {
				t.Fatalf("SerializeAndSign(): %v, want %v", err, tc.want)
			}
		})
	}
}

func TestCreateAndVerify(t *testing.T) {
	for _, tc := range []struct {
		desc    string
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
		t.Run(tc.desc, func(t *testing.T) {
			index := []byte{}
			userID := "alice"
			appID := "app1"

			m := NewMutation(index, directoryID, appID, userID)
			if err := m.SetPrevious(tc.old, true); err != nil {
				t.Fatalf("NewMutation(%v): %v", tc.old, err)
			}
			if err := m.SetCommitment(tc.data); err != nil {
				t.Fatalf("SetCommitment(%v): %v", tc.data, err)
			}
			if err := m.ReplaceAuthorizedKeys(tc.pubKeys.Keyset()); err != nil {
				t.Fatalf("ReplaceAuthorizedKeys(%v): %v", tc.pubKeys, err)
			}
			update, err := m.SerializeAndSign(tc.signers)
			if err != nil {
				t.Fatalf("SerializeAndSign(): %v", err)
			}
			// Verify mutation.
			oldValue, err := FromLeafValue(tc.old)
			if err != nil {
				t.Fatalf("FromLeafValue(%v): %v", tc.old, err)
			}
			f := New()
			newEntry, err := f.Mutate(oldValue, update.GetEntryUpdate().GetMutation())
			if err != nil {
				t.Fatalf("Mutate(%v): %v", update.GetEntryUpdate().GetMutation(), err)
			}

			if !m.EqualsRequested(newEntry) {
				t.Errorf("EqualsRequested(): false")
			}
		})
	}
}
