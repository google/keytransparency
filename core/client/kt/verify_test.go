// Copyright 2016 Google Inc. All Rights Reserved.
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

package kt

import (
	"testing"

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/trillian/merkle/coniks"

	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian"
)

var (
	primaryUserID = "bob"
	primaryAppID  = "myapp"
	fakeUserID    = "eve"
	profileData   = []byte("key")
)

func TestVerifyCommitment(t *testing.T) {
	commitment, committed, err := commitments.Commit(primaryUserID, primaryAppID, profileData)
	if err != nil {
		t.Fatalf("Commit(%v, %v)=%v", primaryUserID, profileData, err)
	}

	entry := &tpb.Entry{Commitment: commitment}
	validEntryData, err := proto.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal(%v)=%v", entry, err)
	}
	fakeEntryData := validEntryData[:len(validEntryData)-1]

	// Create a dummy client verifier.
	verifier := New(0, nil, coniks.Default, nil, nil)
	for _, tc := range []struct {
		userID, appID string
		entryData     []byte
		committed     *tpb.Committed
		want          bool
	}{
		{primaryUserID, primaryAppID, validEntryData, committed, false}, // Working case
		{primaryUserID, primaryAppID, validEntryData, nil, false},       // nil committed
		{primaryUserID, primaryAppID, fakeEntryData, committed, true},   // Unmarshable entry
	} {
		resp := &tpb.GetEntryResponse{
			Committed: tc.committed,
			LeafProof: &trillian.MapLeafInclusion{
				Leaf: &trillian.MapLeaf{
					LeafValue: tc.entryData,
				},
			},
		}
		err = verifier.VerifyCommitment(tc.userID, tc.appID, resp)
		if got := err != nil; got != tc.want {
			t.Errorf("VerifyCommitment(%v, %v)=%v, want %v", tc.userID, resp, got, tc.want)
		}
	}
}

// TODO(gbelvin): add test for VerifyGetEntryResponse.
