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

	"github.com/google/key-transparency/core/commitments"

	"github.com/golang/protobuf/proto"

	ctmap "github.com/google/key-transparency/core/proto/ctmap"
	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

var (
	primaryUserID = "bob"
	fakeUserID    = "eve"
	profile       = &tpb.Profile{Keys: primaryKeys}
	primaryKeys   = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func TestVerifyCommitment(t *testing.T) {
	profileData, err := proto.Marshal(profile)
	if err != nil {
		t.Fatalf("Marshal(%v)=%v", profile, err)
	}
	commitment, committed, err := commitments.Commit(primaryUserID, profileData)
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
	verifier := New(nil, nil, nil, nil)
	for _, tc := range []struct {
		userID    string
		entryData []byte
		committed *tpb.Committed
		want      bool
	}{
		{primaryUserID, validEntryData, committed, false}, // Working case
		{primaryUserID, validEntryData, nil, false},       // nil committed
		{primaryUserID, fakeEntryData, committed, true},   // Unmarshable entry
	} {
		resp := &tpb.GetEntryResponse{
			Committed: tc.committed,
			LeafProof: &ctmap.GetLeafResponse{
				LeafData: tc.entryData,
			},
		}
		err = verifier.VerifyCommitment(tc.userID, resp)
		if got := err != nil; got != tc.want {
			t.Errorf("VerifyCommitment(%v, %v)=%v, want %v", tc.userID, resp, got, tc.want)
		}
	}
}
