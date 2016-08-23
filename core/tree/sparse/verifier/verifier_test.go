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

package verifier

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/key-transparency/core/tree/sparse"
	"golang.org/x/net/context"
)

var (
	ctx          = context.Background()
	AllZeros     = strings.Repeat("0", 256/4)
	defaultIndex = []string{
		"8000000000000000000000000000000000000000000000000000000000000001",
		"C000000000000000000000000000000000000000000000000000000000000001",
		"4000000000000000000000000000000000000000000000000000000000000001",
	}
)

type Leaf struct {
	index []byte
	value []byte
	nbrs  [][]byte
}

func TestVerifyProof(t *testing.T) {
	verifier := New(sparse.CONIKSHasher)
	for _, tc := range []struct {
		root   []byte
		leaves []Leaf
	}{
		// Verify proof of absence in an empty tree.
		{
			dh("71250841561ccdc8b7825cb9a07d67a59ec5627e92ac1f1e700d7ce7b188cb08"),
			[]Leaf{
				{dh(AllZeros), nil, [][]byte{}},
			},
		},
		// Tree with multiple leaves, each has a single existing neighbor
		// on the way to the root.
		{
			dh("c1aa306d40112068b221384127489a05b5bec5f4d693656cccb68ed1e6b1cc5c"),
			[]Leaf{
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("e9b626486fc3f3b68a60150ebd96ddff851a16d5dfd37d39acbff68bbab7e05d"),
					[]byte{},
				}},
				{dh(defaultIndex[1]), []byte("4"), [][]byte{
					dh("858b8d3a44b0bcb43f5a528b2e2256b64c7dfcc625322a07f3b6acb2643bfa36"),
					[]byte{},
				}},
				{dh(defaultIndex[2]), nil, [][]byte{
					dh("a996ec98672d9c219013ef8d31a1f6997e38b6a6b76f6d8ffa142ad210576831"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("a996ec98672d9c219013ef8d31a1f6997e38b6a6b76f6d8ffa142ad210576831"),
				}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("191dc58ab135ea3f21dc882e2a05cb6518342af5b246400dcaa6fae55ebc7a5a"),
			[]Leaf{
				{dh(defaultIndex[2]), []byte("0"), [][]byte{
					dh("a19b5a4e9defe0511a116e4db409dfc37ef5fec1834e9d1528da070ef1bf6dc5"),
				}},
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("63ee0022d85d60c72e1d92aa76e79f7059b4b962a7238a14f5f6ca8e8d8998c5"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("13b5e760f40079499eed79b125ceb75c415eda044f96b7aeb091649668782f00"),
					dh("a19b5a4e9defe0511a116e4db409dfc37ef5fec1834e9d1528da070ef1bf6dc5"),
				}},
			},
		},
	} {
		// VerifyProof of each leaf in the tree.
		for _, leaf := range tc.leaves {
			// The neighbor list must consists of 256 byte arrays,
			// all are empty except the last len(leaf.nbrs) ones.
			// Those are filled from leaf.nbrs.
			nbrs := make([][]byte, 256)
			for k, nbr := range leaf.nbrs {
				nbrs[256-len(leaf.nbrs)+k] = nbr
			}

			if err := verifier.VerifyProof(nbrs, leaf.index, leaf.value, tc.root); err != nil {
				t.Errorf("VerifyProof(_, %v, _, _)=%v", leaf.index, err)
			}
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
