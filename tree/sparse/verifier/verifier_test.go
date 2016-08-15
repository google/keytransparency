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

	"github.com/google/key-transparency/tree/sparse"
	_ "github.com/mattn/go-sqlite3"
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
	hasher = sparse.CONIKSHasher
	// We insert all leaves and then commit once, so the epoch is 1.
	testEpoch = int64(1)
)

type Leaf struct {
	index []byte
	value []byte
	nbrs  [][]byte
}

func TestVerifyProof(t *testing.T) {
	verifier := New(hasher)
	for _, tc := range []struct {
		root   []byte
		leaves []Leaf
	}{
		// Verify proof of absence in an empty tree.
		{
			dh("d576e4657c5f86ba33a435d1abd22cff4f61de4df0cc16c50bd653b1360b367c"),
			[]Leaf{
				{dh(AllZeros), nil, [][]byte{}},
			},
		},
		// Tree with multiple leaves, each has a single existing neighbor
		// on the way to the root.
		{
			dh("376bcc69fda95cea8455224faf8e5a05eaff9ad943e3ef96aaef910649b52806"),
			[]Leaf{
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("fe9992d1c917b1362bd4aad7c1dbaa10dcaa2649844aed2e3d3407b6f28ea6c0"),
					[]byte{},
				}},
				{dh(defaultIndex[1]), []byte("4"), [][]byte{
					dh("f9369f6c112ff583212b7ff07342a84e3f41cfda101923db76cc5517b23d9a38"),
					[]byte{},
				}},
				{dh(defaultIndex[2]), nil, [][]byte{
					dh("7987058861eb3fd513c2d00b91f42fc9bb6b2d878b5b298f4d6ef0c38f1c5395"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("7987058861eb3fd513c2d00b91f42fc9bb6b2d878b5b298f4d6ef0c38f1c5395"),
				}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("528044b5a83335c074eb8631fdaeddd96d65e420ad3031d88cfe03b1ed6f33eb"),
			[]Leaf{
				{dh(defaultIndex[2]), []byte("0"), [][]byte{
					dh("b2283f973324190e2992523432604a3ce6732aef09d267fbf951840d9a854043"),
				}},
				{dh(defaultIndex[0]), []byte("3"), [][]byte{
					dh("5ff0f6495d23d0be76e524710814c76b55213afe9514d473066f920b5c655ec9"),
				}},
				{dh(AllZeros), nil, [][]byte{
					dh("5ad9ddb4579867b9914df56703bd64502397cf02c1f1178393dfee26548d1259"),
					dh("b2283f973324190e2992523432604a3ce6732aef09d267fbf951840d9a854043"),
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
