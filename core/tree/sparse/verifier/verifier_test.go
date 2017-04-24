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

	"github.com/google/keytransparency/core/tree/sparse"
	"golang.org/x/net/context"

	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
)

const mapID = 0

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

/*
// generateNbrData constructs an in-memory tree, fills it with the provided leaves
// and returns a slice of inclusion proofs, one for each leaf.
func generateNbrData(t *testing.T, leaves []Leaf) ([][][]byte, error) {
	// Generate test data.
	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: 1})
	sqldb, err := sql.Open("sqlite3", "file:dummy.db?mode=memory&cache=shared")
	if err != nil {
		return nil, err
	}
	factory := transaction.NewFactory(sqldb, nil)
	m, err := sqlhist.New(context.Background(), sqldb, mapID, factory)
	if err != nil {
		return nil, err
	}
	for _, l := range leaves {
		txn, err := factory.NewTxn(context.Background())
		if err != nil {
			return nil, err
		}
		m.QueueLeaf(txn, l.index, l.value)
		if err := txn.Commit(); err != nil {
			return nil, err
		}
	}
	m.Commit(context.Background())
	ret := make([][][]byte, 0)
	for _, l := range leaves {
		nbrs, err := m.NeighborsAt(context.Background(), l.index, m.Epoch())
		if err != nil {
			return nil, err
		}
		ret = append(ret, nbrs)
	}
	return ret, nil
}
*/

func TestVerifyProof(t *testing.T) {
	verifier := New(mapID, sparse.CONIKSHasher)
	for _, tc := range []struct {
		root   []byte
		leaves []Leaf
	}{
		// Verify proof of absence in an empty tree.
		{
			dh("c2fbf0c12eb8ef812d24d08719fdf43bb805595386409baf0150c5e0947e49cd"),
			[]Leaf{
				{dh(AllZeros), nil, [][]byte{}},
			},
		},
		// Tree with multiple leaves, each has a single existing neighbor
		// on the way to the root.
		{
			dh("58f340a870902df3604315000a0e3ab8c5e6969cfe2ed1ad48c2b8900a72de37"),
			[]Leaf{
				{
					dh(defaultIndex[0]),
					[]byte("3"),
					[][]byte{
						dh("1cf3d1d90436e6ad75eb2ff97816ffcad6f024c6eceb7b86b2c507efdf3567d7"),
						{},
					}},
				{
					dh(defaultIndex[1]),
					[]byte("4"),
					[][]byte{
						dh("9ddd8781499f29bf51b9047da91e23d6fb18ea8b0439e4f10413ddd280cf2d20"),
						{},
					}},
				{
					dh(defaultIndex[2]),
					nil,
					[][]byte{
						dh("0a1db26319a01c8cef10b06c48d6dccce9ac5b951d5b91583a8346530d3d32a5"),
					}},
				{
					dh(AllZeros),
					nil,
					[][]byte{
						dh("0a1db26319a01c8cef10b06c48d6dccce9ac5b951d5b91583a8346530d3d32a5"),
					}},
			},
		},
		// Tree with multiple leaves, some have multiple existing
		// neighbors on the way to the root.
		{
			dh("bfb7ba5e680bb1382982f1d769733bea32eb602787b1064ebb9f699c1d1710ca"),
			[]Leaf{
				{
					dh(defaultIndex[2]),
					[]byte("0"),
					[][]byte{
						dh("0a1db26319a01c8cef10b06c48d6dccce9ac5b951d5b91583a8346530d3d32a5"),
					}},
				{
					dh(defaultIndex[0]),
					[]byte("3"),
					[][]byte{
						dh("1cf3d1d90436e6ad75eb2ff97816ffcad6f024c6eceb7b86b2c507efdf3567d7"),
						dh("22ed79bb41e8dbaf185691deee13645e6bd1d6faee90dc6d33b7a1342aa35555"),
					}},
				{
					dh(AllZeros),
					nil,
					[][]byte{
						dh("a714420de960d9c19e8963301cd7879762cf8255b06d383fba0ea8ab82d5b1c5"),
						dh("0a1db26319a01c8cef10b06c48d6dccce9ac5b951d5b91583a8346530d3d32a5"),
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

			if err := verifier.VerifyProof(nbrs, leaf.index, leaf.value, sparse.FromBytes(tc.root)); err != nil {
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
