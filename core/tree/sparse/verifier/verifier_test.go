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
			dh("4a1d580869a6ed8949b0035be5bfbd52085749f52b83d7eb7fab2340fdeb6070"),
			[]Leaf{
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("87bf45e808101bfd5e564dd2eed054c0879da7b0407ef895be2c1a99645da454"),
					[]byte{},
				}},
				{dh(defaultIndex[1]), []byte("4"), [][]byte{
					dh("dfecc3e854af9140e5224942719b5ad23d637612dc146fcd600a1679d6956797"),
					[]byte{},
				}},
				{dh(defaultIndex[2]), nil, [][]byte{
					dh("cedff4217d4b07261f009ef2331fd286fa1a7a2edbc1b5f4783735aeee02d692"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("cedff4217d4b07261f009ef2331fd286fa1a7a2edbc1b5f4783735aeee02d692"),
				}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("0930a343db7e987c9635351fb8c03f9cf51cbec8e4bfd2faf5acd3c29eb9a945"),
			[]Leaf{
				{dh(defaultIndex[2]), []byte("0"), [][]byte{
					dh("a5535c120ea1a8aa2918119d1b8123d447c1e0a95b994671f20e563ac472a7b6"),
				}},
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("34b5001fe4bbe7d1454f7d216c51ccb5016f980d94220015124c2d28396205a4"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("f98aa36ec5551cd216db932d2ac1d6069690c6d1189aa4dc9185bf2336410ffa"),
					dh("a5535c120ea1a8aa2918119d1b8123d447c1e0a95b994671f20e563ac472a7b6"),
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
