// Copyright 2015 Google Inc. All Rights Reserved.
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

package tree

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
)

var (
	// Zero is the value used to represent 0 in the index bit string.
	Zero = byte('0')
	// One is the data used to represent 1 in the index bit string.
	One = byte('1')
)

// bitString converts a byte slice index into a string of Depth '0' or '1'
// characters.
func BitString(index []byte) string {
	i := new(big.Int)
	i.SetString(hex.EncodeToString(index), 16)
	// A 256 character string of bits with leading Zeros.
	return fmt.Sprintf("%0256b", i)
}

// Neighbor converts Zero into One and visa versa.
func Neighbor(b uint8) uint8 {
	switch b {
	case Zero:
		return One
	case One:
		return Zero
	default:
		log.Fatalf("invalid bit %v", b)
		return 0
	}
}

// path returns all the intermediate nodes between a leaf node and the root, ending with the root.
func Path(bindex string) []string {
	steps := len(bindex) // levels - 1
	n := make([]string, steps)
	for i := 0; i < steps; i++ {
		n[i] = bindex[:steps-i]
	}
	n = append(n, "") // Append a root node.
	return n
}

// Neighbors returns a list of all Neighbors from the leaf level up to the root-1.
func Neighbors(bindex string) []string {
	steps := len(bindex) // levels - 1
	n := make([]string, steps)
	for i := 0; i < steps; i++ {
		n[i] = NeighborString(bindex[:steps-i])
	}
	return n
}

// Neighbor inverts the last Zero into a One and visa versa.
// ps. the root node does not have a Neighbor
func NeighborString(bindex string) string {
	last := len(bindex) - 1
	return fmt.Sprintf("%v%v", bindex[:last], string(Neighbor(bindex[last])))
}
