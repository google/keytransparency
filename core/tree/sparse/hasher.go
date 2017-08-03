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

package sparse

import (
	"crypto"
	"encoding/binary"
)

// TreeHasher provides hash functions for tree implementations.
type TreeHasher interface {
	HashLeaf(mapID int64, index []byte, depth int, dataHash []byte) Hash
	HashInterior(left, right Hash) Hash
	HashEmpty(mapID int64, index []byte, depth int) Hash
}

// CONIKSHasher implements the tree hashes described in CONIKS
// http://www.jbonneau.com/doc/MBBFF15-coniks.pdf
var CONIKSHasher TreeHasher = &coniksHasher{}

type coniksHasher struct{}

var (
	leafIdentifier  = []byte("L")
	emptyIdentifier = []byte("E")
	hash            = crypto.SHA512_256
)

// HashLeaf calculate the merkle tree node value:
// H(Identifier || mapID || depth || index || dataHash)
func (coniksHasher) HashLeaf(mapID int64, index []byte, depth int, dataHash []byte) Hash {
	bmapID := make([]byte, 8)
	binary.BigEndian.PutUint64(bmapID, uint64(mapID))
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	b := hash.New()
	b.Write(leafIdentifier)
	b.Write(bmapID)
	b.Write(index)
	b.Write(bdepth)
	b.Write(dataHash)
	return Hash(b.Sum(nil))
}

// HashInterior calculates an interior node's value: H(left || right)
func (coniksHasher) HashInterior(left, right Hash) Hash {
	b := hash.New()
	b.Write(left.Bytes())
	b.Write(right.Bytes())
	return Hash(b.Sum(nil))
}

// HashEmpty computes the value of an empty leaf:
// H(EmptyIdentifier || mapID || depth || index)
func (coniksHasher) HashEmpty(mapID int64, index []byte, depth int) Hash {
	bmapID := make([]byte, 8)
	binary.BigEndian.PutUint64(bmapID, uint64(mapID))
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	b := hash.New()
	b.Write(emptyIdentifier)
	b.Write(bmapID)
	b.Write(index)
	b.Write(bdepth)
	return Hash(b.Sum(nil))
}
