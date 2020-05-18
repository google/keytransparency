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

package keyserver

import (
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf/p256"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(%T): %v", p, err)
	}
	return b
}

func TestValidateUpdateEntryRequest(t *testing.T) {
	// Create and marshal a profile.
	profileData := []byte("bar")

	// Test verification for new entries.
	userID := "joe"
	vrfPriv, _ := p256.GenerateKey()
	index, _ := vrfPriv.Evaluate([]byte(userID))
	nonce, err := commitments.GenCommitmentKey()
	if err != nil {
		t.Fatal(err)
	}
	commitment := commitments.Commit(userID, profileData, nonce)

	for _, tc := range []struct {
		want       bool
		userID     string
		index      [32]byte
		commitment []byte
		nonce      []byte
	}{
		{false, userID, [32]byte{}, nil, nil},   // Incorrect index
		{false, userID, index, nil, nil},        // Incorrect commitment
		{false, userID, index, commitment, nil}, // Incorrect key
		{true, userID, index, commitment, nonce},
	} {
		req := &pb.EntryUpdate{
			UserId: tc.userID,
			Mutation: &pb.SignedEntry{
				Entry: mustMarshal(t, &pb.Entry{
					Index:      tc.index[:],
					Commitment: tc.commitment,
				}),
			},
			Committed: &pb.Committed{
				Key:  tc.nonce,
				Data: profileData,
			},
		}
		err := validateEntryUpdate(req, vrfPriv)
		if got := err == nil; got != tc.want {
			t.Errorf("validateEntryUpdate(%v): %v, want %v", req, err, tc.want)
		}
	}
}
