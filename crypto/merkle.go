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

package crypto

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/google/e2e-key-server/util"
)

const (
	HASH_BYTES                   = 32
	INTERMEDIATE_NODE_IDENTIFIER = 'I'
	LEAF_IDENTIFIER              = 'L'
)

func HashIntermediateNode(prefixBits []bool, childHashes *[2][HASH_BYTES]byte) []byte {
	buf := make([]byte, 5)
	buf[0] = INTERMEDIATE_NODE_IDENTIFIER
	binary.LittleEndian.PutUint32(buf[1:], uint32(len(prefixBits)))
	h := sha256.New()
	h.Write(buf)
	h.Write(childHashes[0][:])
	h.Write(childHashes[1][:])
	h.Write(util.ToBytes(prefixBits))
	return h.Sum(nil)
}

func HashLeaf(indexBytes []byte, commitment []byte) []byte {
	h := sha256.New()
	h.Write([]byte{LEAF_IDENTIFIER})
	h.Write(indexBytes)
	h.Write(commitment)
	return h.Sum(nil)
}
