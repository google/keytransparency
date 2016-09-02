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
	"bytes"
	"crypto/sha512"
	"encoding/binary"
)

// TreeHasher provides hash functions for tree implementations.
type TreeHasher interface {
	HashLeaf(mapID, index []byte, depth int, dataHash []byte) Hash
	HashInterior(left, right Hash) Hash
	HashEmpty(mapID, index []byte, depth int) Hash
}

// CONIKSHasher implements the tree hashes described in CONIKS
// http://www.jbonneau.com/doc/MBBFF15-coniks.pdf
var CONIKSHasher TreeHasher = &coniks{}

type coniks struct{}

var (
	leafIdentifier  = []byte("L")
	emptyIdentifier = []byte("E")
	hash            = sha512.Sum512_256
)

// HashLeaf calculate the merkle tree node value:
// H(Identifier || mapID || depth || index || dataHash)
func (coniks) HashLeaf(mapID, index []byte, depth int, dataHash []byte) Hash {
	bmapIDLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bmapIDLen, uint32(len(mapID)))
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	var b bytes.Buffer
	b.Write(leafIdentifier)
	b.Write(bmapIDLen)
	b.Write(mapID)
	b.Write(index)
	b.Write(bdepth)
	b.Write(dataHash)
	return Hash(hash(b.Bytes()))
}

// HashInterior calculates an interior node's value: H(left || right)
func (coniks) HashInterior(left, right Hash) Hash {
	var b bytes.Buffer
	b.Write(left.Bytes())
	b.Write(right.Bytes())
	return Hash(hash(b.Bytes()))
}

// HashEmpty computes the value of an empty leaf:
// H(EmptyIdentifier || mapID || depth || index)
func (coniks) HashEmpty(mapID, index []byte, depth int) Hash {
	bmapIDLen := make([]byte, 4)
	binary.BigEndian.PutUint32(bmapIDLen, uint32(len(mapID)))
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))

	var b bytes.Buffer
	b.Write(emptyIdentifier)
	b.Write(bmapIDLen)
	b.Write(mapID)
	b.Write(index)
	b.Write(bdepth)
	return Hash(hash(b.Bytes()))
}
