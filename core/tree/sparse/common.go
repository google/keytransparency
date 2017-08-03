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

// Package merkle implements a time series prefix tree. Each epoch has its own
// prefix tree. By default, each new epoch is equal to the contents of the
// previous epoch.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.

package sparse

import (
	"crypto/sha512"
	"fmt"

	"github.com/google/keytransparency/core/tree"
	"github.com/google/trillian/merkle/hashers"
)

const (
	// HashSize contains the blocksize of the used hash function in bytes.
	HashSize = sha512.Size256
	// IndexLen is the maximum number of levels in this Merkle Tree.
	IndexLen = HashSize * 8
)

// Hash represents the output of the hash function used in the sparse tree.
type Hash []byte

// NodeValues computes the new values for leafs up the tree. nbrValues must not
// be compressed. value is the actual value of the leaf. NodeValues returns the
// leaf hash as part of the returned list.
func NodeValues(mapID int64, hasher hashers.MapHasher, bindex string, value []byte, nbrValues []Hash) []Hash {
	levels := len(bindex) + 1
	steps := len(bindex)
	nodeValues := make([]Hash, levels)
	index, depth := tree.InvertBitString(bindex)
	nodeValues[0] = hasher.HashLeaf(mapID, index, depth, value)
	// assert len(nbrValues) == levels - 1
	for i := 0; i < steps; i++ {
		// Is the last node 0 or 1?
		var left, right Hash
		if bindex[steps-i-1] == tree.Zero {
			left = nodeValues[i]
			right = nbrValues[i]
		} else {
			left = nbrValues[i]
			right = nodeValues[i]
		}
		nodeValues[i+1] = hasher.HashChildren(left, right)
	}
	return nodeValues
}

// FromBytes initializes a Hash object from a byte slice.
func FromBytes(b []byte) Hash {
	if len(b) != HashSize {
		panic(fmt.Sprintf("sparse.FromBytes(%x) len %d, want %d", b, len(b), HashSize))
	}
	var h Hash
	copy(h[:], b)
	return h
}

// Bytes returns a byte slice from a Hash object.
func (h Hash) Bytes() []byte {
	return h[:]
}
