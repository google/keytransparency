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
	"bytes"
	"encoding/hex"
	"testing"
)

// Use a constant key of zero to obtain consistent test vectors.
// Real commitment library MUST use random keys.
var zeroKey = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func TestCommit(t *testing.T) {
	for _, tc := range []struct {
		userID, data   string
		muserID, mdata string
		mutate         bool
		want           error
	}{
		{"foo", "bar", "foo", "bar", false, nil},
		{"foo", "bar", "fo", "obar", false, ErrInvalidCommitment},
		{"foo", "bar", "foob", "ar", false, ErrInvalidCommitment},
	} {
		data := []byte(tc.data)
		c := Commit(tc.userID, data, zeroKey)
		if tc.mutate {
			c[0] ^= 1
		}
		if got := Verify(tc.muserID, c, data, zeroKey); got != tc.want {
			t.Errorf("Verify(%v, %x, %x, %x): %v, want %v", tc.userID, c, data, zeroKey, got, tc.want)
		}
	}
}

func TestVectors(t *testing.T) {
	for _, tc := range []struct {
		userID, data string
		want         []byte
	}{
		{"", "", dh("30094c7227737fc4694f83759427044290281e0ed2ddc475726feb491d99a9c9")},
		{"foo", "bar", dh("85425456c59c8af715d352477b2883beea5fc7399d8946d6716285b058b9813c")},
		{"foo1", "bar", dh("9570f81783f11df56c5ed3efc7f03a0fd58c8f404cc0f46b5ec4aefdb94fba45")},
		{"foo", "bar1", dh("cdfc663f9403bc2c6104e5c95cef08403745bf309525ba56147d601041f83d04")},
	} {
		data := []byte(tc.data)
		if got, want := Commit(tc.userID, data, zeroKey), tc.want; !bytes.Equal(got, want) {
			t.Errorf("Commit(%v, %v): %x ,want %x", tc.userID, tc.data, got, want)
		}
	}
}

// Hex to Bytes
func dh(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
