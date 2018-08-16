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
		{"", "", "", dh("c0ed0ecc3801a7d66fd86f37dbaf9d6853b7829a320036f21035adced508df1a")},
		{"foo", "app", "bar", dh("f686de3c4ccfe52724f8067b95a9d2030df73353ed548a1b6d8e334d16bcac57")},
		{"foo1", "app", "bar", dh("c5eff3426ff412ca9976186aa188b7eacdaaec9743536f9524ada564bdf78543")},
		{"foo", "app1", "bar", dh("0d7f40c12fc912f971f4afce7fa44a034b38aca299b8a4b29800ba45bec79148")},
		{"foo", "app", "bar1", dh("a42a7e606753b61964e0333823939baeda4cd0c80583af0aa6d71dadec6e5bb8")},
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
