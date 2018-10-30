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

package vrf

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestUniqueID(t *testing.T) {
	for _, tc := range []struct {
		userID  string
		muserID string
	}{
		{"foo", "fooa"},
		{"foo", ""},
		{"foo", "fooapp"},
	} {
		if got, want :=
			UniqueID(tc.userID),
			UniqueID(tc.muserID); bytes.Equal(got, want) {
			t.Errorf("UniqueID(%v) == UniqueID(%v): %s, want !=", tc.userID, tc.muserID, got)
		}
	}
}

func TestUniqueIDTestVector(t *testing.T) {
	for _, tc := range []struct {
		userID   string
		expected []byte
	}{
		{"foo", dh("00000003666f6f")},
		{"foobar", dh("00000006666f6f626172")},
	} {
		if got, want := UniqueID(tc.userID), tc.expected; !bytes.Equal(got, want) {
			t.Errorf("UniqueID(%v): %x, want %v", tc.userID, got, want)
		}
	}
}

func dh(h string) []byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic(err)
	}
	return b
}
