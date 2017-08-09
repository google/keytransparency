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
		userID, appID, data    string
		muserID, mappID, mdata string
		mutate                 bool
		want                   error
	}{
		{"foo", "app", "bar", "foo", "app", "bar", false, nil},
		{"foo", "app", "bar", "foo", "app", "bar", true, ErrInvalidCommitment},
		{"foo", "app", "bar", "fooa", "pp", "bar", false, ErrInvalidCommitment},
		{"foo", "app", "bar", "foo", "ap", "pbar", false, ErrInvalidCommitment},
	} {
		data := []byte(tc.data)
		c := Commit(tc.userID, tc.appID, data, zeroKey)
		if tc.mutate {
			c[0] ^= 1
		}
		if got := Verify(tc.muserID, tc.mappID, c, data, zeroKey); got != tc.want {
			t.Errorf("Verify(%v, %v, %x, %x, %x): %v, want %v",
				tc.userID, tc.appID, c, data, zeroKey, got, tc.want)
		}
	}
}

func TestVectors(t *testing.T) {
	for _, tc := range []struct {
		userID, appID, data string
		want                []byte
	}{
		{"", "", "", dh("0698789c7beed09e93848e4df08be5c911de534d286abcbf69359debe4c62bc2")},
		{"foo", "app", "bar", dh("064c8933f50f897e8b179065c6b3ec13e9d093337c6d403c77e3ed1701378ed6")},
		{"foo1", "app", "bar", dh("77015921f7fe584e1b5866a32ab9f305715c4e0241581d41f66ee34b24cdb566")},
		{"foo", "app1", "bar", dh("e7337229d7747cc2c9a83ee08adbec712f4acafd1b72258bbebf74637de987b7")},
		{"foo", "app", "bar1", dh("0fa2d7d53552e0871564c0e82ad394e72476b75f7fc77f40e2080af7f33d66eb")},
	} {
		data := []byte(tc.data)
		if got, want := Commit(tc.userID, tc.appID, data, zeroKey), tc.want; !bytes.Equal(got, want) {
			t.Errorf("Commit(%v, %x): %x ,want %x", tc.userID, tc.data, got, want)
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
