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
	"crypto/sha512"
	"encoding/binary"
)

// TreeHasher provides hash functions for tree implementations.
type TreeHasher interface {
	HashLeaf(index []byte, depth int, dataHash []byte) []byte
	HashChildren(left []byte, right []byte) []byte
	HashEmpty(index []byte, depth int) []byte
}

// Coniks implements the tree hashes described in CONIKS
// http://www.jbonneau.com/doc/MBBFF15-coniks.pdf
var Coniks TreeHasher = &coniks{}

type coniks struct{}

var (
	leafIdentifier  = []byte("L")
	emptyIdentifier = []byte("E")
	newHash         = sha512.New512_256
)

// HashLeaf calculate the merkle tree node value:
// H(Identifier || depth || index || dataHash)
func (c coniks) HashLeaf(index []byte, depth int, dataHash []byte) []byte {
	return c.hashLeaf(leafIdentifier, index, depth, dataHash)
}

// HashChildren calculates an interior node's value: H(left || right)
func (coniks) HashChildren(left []byte, right []byte) []byte {
	h := newHash()
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// HashEmpty computes the value of an empty leaf:
// H(EmptyIdentifier || depth || index)
func (c coniks) HashEmpty(index []byte, depth int) []byte {
	return c.hashLeaf(emptyIdentifier, index, depth, nil)
}

func (coniks) hashLeaf(identifier []byte, index []byte, depth int, dataHash []byte) []byte {
	bdepth := make([]byte, 4)
	binary.BigEndian.PutUint32(bdepth, uint32(depth))
	h := newHash()
	h.Write(identifier)
	h.Write(bdepth)
	h.Write(index)
	h.Write(dataHash)
	return h.Sum(nil)
}
