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

package sparse

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// h2h converts a hex string into its Hash object.
func h2h(h string) Hash {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("invalid hex string")
	}
	return b
}

func TestHashLeafVectors(t *testing.T) {
	for _, tc := range []struct {
		treeID int64
		index  []byte
		depth  int
		leaf   []byte
		want   Hash
	}{
		{treeID: 0, index: []byte("foo"), depth: 128, leaf: []byte("leaf"), want: h2h("2d6c9f648b61e786e18bcba49d1dc62dee2020cec168f0d2c9e47a7bd4633f02")},
	} {
		if got, want := CONIKSHasher.HashLeaf(tc.treeID, tc.index, tc.depth, tc.leaf), tc.want; !bytes.Equal(got, want) {
			t.Errorf("HashLeaf(%v, %s, %v, %s): %x, want %x", tc.treeID, tc.index, tc.depth, tc.leaf, got, want)
		}
	}
}

func TestHashEmptyVectors(t *testing.T) {
	for _, tc := range []struct {
		treeID int64
		index  []byte
		depth  int
		want   Hash
	}{
		{treeID: 0, index: []byte("foo"), depth: 128, want: h2h("6db629ab14386f31c5f573a5734d7f3c50d97bf06fa0da606dad47b8b1a3eb32")},
	} {
		if got, want := CONIKSHasher.HashEmpty(tc.treeID, tc.index, tc.depth), tc.want; !bytes.Equal(got, want) {
			t.Errorf("HashEmpty(%v, %s, %v): %x, want %x", tc.treeID, tc.index, tc.depth, got, want)
		}
	}
}
