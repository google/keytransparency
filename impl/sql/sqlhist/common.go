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

package sqlhist

import (
	"crypto/sha256"
	"fmt"
)

const idSize = sha256.Size

// ID is a type reflecting node and leaf ID values.
type ID [idSize]byte

// FromBytes initializes a Hash object from a byte slice.
func FromBytes(b []byte) ID {
	if len(b) != idSize {
		panic(fmt.Sprintf("id len != %v", idSize))
	}
	var id ID
	copy(id[:], b)
	return id
}

// Bytes returns a byte slice from a Hash object.
func (id ID) Bytes() []byte {
	return id[:]
}
