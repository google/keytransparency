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

// Package commitments contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package commitments

import (
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	pb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

func TestCommit(t *testing.T) {
	for _, tc := range []struct {
		userID  string
		profile *pb.Profile
		mutate  bool
		want    error
	}{
		{"foo", &pb.Profile{}, false, nil},
		{"foo", &pb.Profile{}, true, ErrInvalidCommitment},
	} {
		a, err := ptypes.MarshalAny(tc.profile)
		if err != nil {
			t.Errorf("Failed to marshal profile: %v", err)
		}
		k, c, err := Commit(tc.userID, a)
		if err != nil {
			t.Errorf("Commit(%v, %x): %v", tc.userID, tc.profile, err)
		}
		if tc.mutate {
			k[0] ^= 1
		}

		if got := Verify(tc.userID, k, c); got != tc.want {
			t.Errorf("Verify(%v, %x, %v): %v, want %v", tc.userID, k, c, err, tc.want)
		}
	}
}

func TestObjectHash(t *testing.T) {
	// Verify that object hash produces unique results for various any.Any objects.
	hashes := make(map[[32]byte]bool)
	// Use zero keys to test object hash differentiation.
	randReader = func(b []byte) (n int, err error) {
		for i := range b {
			b[i] = 0
		}
		return len(b), nil
	}
	for _, tc := range []proto.Message{
		&pb.Profile{},
		&pb.Profile{Keys: map[string][]byte{"": []byte{}}},
		&pb.Profile{Keys: map[string][]byte{"foo": []byte("bar")}},
		&pb.Committed{},
	} {
		a, err := ptypes.MarshalAny(tc)
		if err != nil {
			t.Errorf("MashalAny(%v): %v", tc, err)
		}
		userID := ""
		k, _, err := Commit(userID, a)
		if err != nil {
			t.Errorf("Commit(%v, %v): %v", userID, a, err)
		}

		// Verify that the hash doesn't conflict with any previous hashes.
		var h [32]byte
		copy(h[:], k[0:32])
		if ok := hashes[h]; ok {
			t.Errorf("Commit(%v, %+v): %x, conflicts with preivous commitment", userID, a, h)
		}
		hashes[h] = true
	}
}
