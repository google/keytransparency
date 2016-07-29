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
	"crypto/sha256"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/key-transparency/commitments"
	"github.com/google/key-transparency/vrf"
	"github.com/google/key-transparency/vrf/p256"

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
	fakeCommitted := &pb.Committed{
		Key:  []byte{0},
		Data: []byte{1},
	}

	tests := []struct {
		userID     string
		commitment []byte
		committed  *pb.Committed
		err        error
	}{
		{primaryUserID, commitment, committed, nil},                                  // Working case
		{primaryUserID, commitment, nil, nil},                                        // nil committed
		{primaryUserID, commitment, fakeCommitted, commitments.ErrInvalidCommitment}, // Wrong committed
		{primaryUserID, nil, committed, commitments.ErrInvalidCommitment},            // Wrong commitment
		{primaryUserID, nil, nil, nil},                                               // Wrong commitment and nil committed
		{primaryUserID, nil, fakeCommitted, commitments.ErrInvalidCommitment},        // Wrong commitment and committed
		{fakeUserID, commitment, committed, commitments.ErrInvalidCommitment},        // Wrong user
		{fakeUserID, commitment, nil, nil},                                           // Wrong user and nil committed
		{fakeUserID, commitment, fakeCommitted, commitments.ErrInvalidCommitment},    // Wrong user and committed
		{fakeUserID, nil, committed, commitments.ErrInvalidCommitment},               // Wrong user and commitment
		{fakeUserID, nil, nil, nil},                                                  // Wrong user, commitment and nil committed
		{fakeUserID, nil, fakeCommitted, commitments.ErrInvalidCommitment},           // Wrong user, commitment and committed
	}

	for i, tc := range tests {
		entry := &pb.Entry{Commitment: tc.commitment}
		entryData, err := proto.Marshal(entry)
		if err != nil {
			t.Fatalf("Marshal(%v)=%v", entry, err)
		}
		resp := &pb.GetEntryResponse{
			Committed: tc.committed,
			LeafProof: &ctmap.GetLeafResponse{
				LeafData: entryData,
			},
		}
		if got, want := VerifyCommitment(tc.userID, resp), tc.err; got != want {
			t.Errorf("%v: VerifyCommitment(%v, %v)=%v, want %v", i, tc.userID, resp, got, want)
		}
	}
}

func TestVerifyVRF(t *testing.T) {
	k, pk := p256.GenerateKey()
	_, wrongPK := p256.GenerateKey()
	vrfValue, proof := k.Evaluate([]byte(primaryUserID))
	vrfIndex := sha256.Sum256(vrfValue)
	fake := [32]byte{}

	tests := []struct {
		userID string
		vrf    []byte
		proof  []byte
		pk     vrf.PublicKey
		err    error
		index  [32]byte
	}{
		{primaryUserID, vrfValue, proof, pk, nil, vrfIndex},              // Working case
		{primaryUserID, vrfValue, proof, wrongPK, ErrInvalidVRF, fake},   // Wrong pk
		{primaryUserID, vrfValue, fake[:], pk, ErrInvalidVRF, fake},      // Wrong proof
		{primaryUserID, vrfValue, fake[:], wrongPK, ErrInvalidVRF, fake}, // Wrong proof, and pk
		{primaryUserID, fake[:], proof, pk, ErrInvalidVRF, fake},         // Wrong vrf
		{primaryUserID, fake[:], proof, wrongPK, ErrInvalidVRF, fake},    // Wrong vrf and pk
		{primaryUserID, fake[:], fake[:], pk, ErrInvalidVRF, fake},       // Wrong vrf and proof
		{primaryUserID, fake[:], fake[:], wrongPK, ErrInvalidVRF, fake},  // Wrong vrf, proof, and pk
		{fakeUserID, vrfValue, proof, pk, ErrInvalidVRF, vrfIndex},       // Wrong user
		{fakeUserID, vrfValue, proof, wrongPK, ErrInvalidVRF, fake},      // Wrong user and pk
		{fakeUserID, vrfValue, fake[:], pk, ErrInvalidVRF, fake},         // Wrong user and proof
		{fakeUserID, vrfValue, fake[:], wrongPK, ErrInvalidVRF, fake},    // Wrong user, proof, and pk
		{fakeUserID, fake[:], proof, pk, ErrInvalidVRF, fake},            // Wrong user and vrf
		{fakeUserID, fake[:], proof, wrongPK, ErrInvalidVRF, fake},       // Wrong user, vrf and key
		{fakeUserID, fake[:], fake[:], pk, ErrInvalidVRF, fake},          // Wrong user, vrf and proof
		{fakeUserID, fake[:], fake[:], wrongPK, ErrInvalidVRF, fake},     // Wrong user, vrf, proof and pk
	}

	for i, tc := range tests {
		resp := &pb.GetEntryResponse{
			Vrf:      tc.vrf,
			VrfProof: tc.proof,
		}
		index, err := VerifyVRF(tc.userID, resp, tc.pk)
		if got, want := err, tc.err; got != want {
			t.Errorf("%v: VerifyVRF(%v, %v, %v)=(_, %v)", i, tc.userID, resp, tc.pk, got, want)
		}

		// Cannot continue with testing index if VerifyVRF returns error.
		if err == nil {
			if got, want := index, tc.index; got != want {
				t.Errorf("%v: VerifyVRF(%v, %v, %v)=(%v, _)", i, tc.userID, resp, tc.pk, got, want)
			}
		}
	}
}

// TODO: write tests for verifyLog.
