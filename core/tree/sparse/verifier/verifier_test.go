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

const mapID = "verifyMap"

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
	verifier := New([]byte(mapID), sparse.CONIKSHasher)
	for _, tc := range []struct {
		root   []byte
		leaves []Leaf
	}{
		// Verify proof of absence in an empty tree.
		{
			dh("36d699dd75f74edb84789d1bf301a9c2ff8dc815b70f5afc8ec156f5ae102c65"),
			[]Leaf{
				{dh(AllZeros), nil, [][]byte{}},
			},
		},
		// Tree with multiple leaves, each has a single existing neighbor
		// on the way to the root.
		{
			dh("c84c416481ee9610ac80cbcafc000caf0ef9210a3494fe60610339cceb94ca51"),
			[]Leaf{
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("90a89a487fe9ce56f0d09e10521f49dc359352e6df2e651fd9dfda5576ef301d"),
					[]byte{},
				}},
				{dh(defaultIndex[1]), []byte("4"), [][]byte{
					dh("56bb3dea5b1917f78ceada1e30aa6ef3eb10c92e853a184920bc77ebba880c97"),
					[]byte{},
				}},
				{dh(defaultIndex[2]), nil, [][]byte{
					dh("a54055bcae7a5b30437a8019d06cc4d3e9bc7ed4ebd61b7788ae6b37c519376e"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("a54055bcae7a5b30437a8019d06cc4d3e9bc7ed4ebd61b7788ae6b37c519376e"),
				}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("6a4fc1a01ccd5bf4a04d10024caf32f64a6b31ac3abc33ed226f2477c2e1538a"),
			[]Leaf{
				{dh(defaultIndex[2]), []byte("0"), [][]byte{
					dh("70d6b51a07afec6df56009534ea66b3d582882b682b2984379e1a1f521d2226f"),
				}},
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("ac94e5c10744333c8fd6cdf4eb7064d10e269ced005659b4c92380eed0606fad"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("568fa9c30d8fe3dbe8d7f4dc112d41581e4583a9dc77e61030f36fd22c83247b"),
					dh("70d6b51a07afec6df56009534ea66b3d582882b682b2984379e1a1f521d2226f"),
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
