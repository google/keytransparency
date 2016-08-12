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

package client

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/key-transparency/commitments"

	ctmap "github.com/google/key-transparency/proto/ctmap"
	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

var (
	primaryUserID = "bob"
	fakeUserID    = "eve"
	profile       = &pb.Profile{Keys: primaryKeys}
	primaryKeys   = map[string][]byte{
		"foo": []byte("bar"),
	}
)

func TestVerifyCommitment(t *testing.T) {
	profileData, err := proto.Marshal(profile)
	if err != nil {
		t.Fatalf("Marshal(%v)=%v", profile, err)
	}
	commitment, committed, err := commitments.CommitName(primaryUserID, profileData)
	if err != nil {
		t.Fatalf("CommitName(%v, %v)=%v", primaryUserID, profileData, err)
	}

	entry := &pb.Entry{Commitment: commitment}
	validEntryData, err := proto.Marshal(entry)
	if err != nil {
		t.Fatalf("Marshal(%v)=%v", entry, err)
	}
	fakeEntryData := validEntryData[:len(validEntryData)-1]

	tests := []struct {
		userID    string
		entryData []byte
		committed *pb.Committed
		want      bool
	}{
		{primaryUserID, validEntryData, committed, false}, // Working case
		{primaryUserID, validEntryData, nil, false},       // nil committed
		{primaryUserID, fakeEntryData, committed, true},   // Unmarshable entry
	}

	for _, tc := range tests {
		resp := &pb.GetEntryResponse{
			Committed: tc.committed,
			LeafProof: &ctmap.GetLeafResponse{
				LeafData: tc.entryData,
			},
		}
		err = VerifyCommitment(tc.userID, resp)
		if got := err != nil; got != tc.want {
			t.Errorf("VerifyCommitment(%v, %v)=%v, want %v", tc.userID, resp, got, tc.want)
		}
	}
}

// TODO: write tests for verifyLog.
