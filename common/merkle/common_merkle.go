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

// This package contains merkle tree common type definitions and functions used
// by other packages. Types that can cause circular import should be added here.
package common_merkle

import (
	"crypto/sha256"
	"encoding/binary"
)

const (
	// HashSize contains the blocksize of the used hash function in bytes.
	HashSize = sha256.Size
	// IndexLen is the maximum number of levels in this Merkle Tree.
	IndexLen = HashSize * 8
	// commitmentKeyLen is the number of bytes required to be in the
	// profile commitment.
	commitmentKeyLen = 16
)

var (
	// LeafIdentifier is the data used to indicate a leaf node.
	LeafIdentifier = []byte("L")
	// EmptyIdentifier is used while calculating the data of nil sub branches.
	EmptyIdentifier = []byte("E")
)

// HashLeaf calculate the merkle tree leaf node value. This is computed as
// H(Identifier || depth || index || dataHash), where Identifier, depth, and
// index are fixed-length.
func HashLeaf(identifier []byte, depth int, index []byte, dataHash []byte) []byte {
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	h := sha256.New()
	h.Write(identifier)
	h.Write(bdepth)
	h.Write(index)
	h.Write(dataHash)
	return h.Sum(nil)
}

// HashIntermediateNode calculates an interior node's value by H(left || right)
func HashIntermediateNode(left []byte, right []byte) []byte {
	h := sha256.New()
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
