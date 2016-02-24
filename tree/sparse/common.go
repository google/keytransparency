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
	"encoding/binary"

	"github.com/google/e2e-key-server/tree"
)

const (
	// HashSize contains the blocksize of the used hash function in bytes.
	HashSize = sha512.Size256
	// IndexLen is the maximum number of levels in this Merkle Tree.
	IndexLen = HashSize * 8
)

var (
	// LeafIdentifier is the data used to indicate a leaf node.
	LeafIdentifier = []byte("L")
	// EmptyIdentifier is used while calculating the data of nil sub branches.
	EmptyIdentifier = []byte("E")

	NewHash = sha512.New512_256
)

// HashLeaf calculate the merkle tree leaf node value. This is computed as
// H(Identifier || depth || index || dataHash), where Identifier, depth, and
// index are fixed-length.
func HashLeaf(identifier []byte, depth int, index []byte, dataHash []byte) []byte {
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	h := NewHash()
	h.Write(identifier)
	h.Write(bdepth)
	h.Write(index)
	h.Write(dataHash)
	return h.Sum(nil)
}

// HashIntermediateNode calculates an interior node's value by H(left || right)
func HashIntermediateNode(left []byte, right []byte) []byte {
	h := NewHash()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyLeafValue computes the value of an empty leaf as
// H(EmptyIdentifier || depth || index), where EmptyIdentifier, depth, and
// index are fixed-length.
func EmptyLeafValue(prefix string) []byte {
	return HashLeaf(EmptyIdentifier, len(prefix), []byte(prefix), nil)
}

// NodeValues computes the new values for nodes up the tree.
func NodeValues(bindex string, leafHash []byte, nbrValues [][]byte) [][]byte {
	levels := len(bindex) + 1
	steps := len(bindex)
	nodeValues := make([][]byte, levels)
	nodeValues[0] = leafHash
	// assert len(nbrValues) == levels - 1
	for i := 0; i < steps; i++ {
		// Is the last node 0 or 1?
		var left, right []byte
		if bindex[steps-i-1] == tree.Zero {
			left = nodeValues[i]
			right = nbrValues[i]
		} else {
			left = nbrValues[i]
			right = nodeValues[i]
		}
		nodeValues[i+1] = HashIntermediateNode(left, right)
	}
	return nodeValues
}
