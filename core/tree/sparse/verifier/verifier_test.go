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
			dh("5bb1d793893ec70dd21a83f4faa94232e0ff9d8c74bc928d3479beb9b82608bc"),
			[]Leaf{
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("d16cfa61bd103aa958da52eccae55715c8a2f2a33663a8397b13d3c2fa31090a"),
					[]byte{},
				}},
				{dh(defaultIndex[1]), []byte("4"), [][]byte{
					dh("30eec702b035570b82889d71db8325b05576a80f327cefeac17c743a7cae88b3"),
					[]byte{},
				}},
				{dh(defaultIndex[2]), nil, [][]byte{
					dh("7184164d16837c61b15e347d20fb6338c5c437edf7e919e0865a59906557ff98"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("7184164d16837c61b15e347d20fb6338c5c437edf7e919e0865a59906557ff98"),
				}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("84b5275ffa8ac9e9fc7afc3bcfb8e69fff186fb675dd6ee25bf1b46d199daea0"),
			[]Leaf{
				{dh(defaultIndex[2]), []byte("0"), [][]byte{
					dh("39d08ffc594fab8829d228e6771f85b63d1a4607606739ccf65e89daebe4deb2"),
				}},
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("e8d949ff3705218835274fe8a04695d1800e72ecb327f2e266821f0b5c21b904"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("68572f8d1ecbd5fa055ec6eed6d2587ee8f7a661c20ef20e5f74465d116c4f8d"),
					dh("39d08ffc594fab8829d228e6771f85b63d1a4607606739ccf65e89daebe4deb2"),
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
