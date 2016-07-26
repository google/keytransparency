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

// Package verifier allows client to verify a tree proof. This package does not
// depend on the actual tree implementation.
package verifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/key-transparency/tree"
	"github.com/google/key-transparency/tree/sparse"
)

var (
	errNeighborsLen = fmt.Errorf("neighbors len > %d", sparse.IndexLen)
	errIndexBit     = errors.New("invalid index bit")
	errInvalidProof = errors.New("invalid proof")
)

// Verifier represents the tree proofs verifier object.
type Verifier struct {
	hasher sparse.TreeHasher
}

// New returns a new tree proofs verifier object.
func New(hasher sparse.TreeHasher) *Verifier {
	return &Verifier{hasher}
}

// VerifyProof verifies a tree proof of a given leaf in a given index based on
// the provided root and neighbor list
func (v *Verifier) VerifyProof(neighbors [][]byte, index, leaf, root []byte) error {
	if len(neighbors) > sparse.IndexLen {
		return errNeighborsLen
	}

	// Calculate the tree root based on neighbors and leaf.
	calculatedRoot, err := v.calculateRoot(neighbors, tree.BitString(index), leaf)
	if err != nil {
		return err
	}

	// Verify that calculated and provided roots match.
	if !bytes.Equal(calculatedRoot, root) {
		return errInvalidProof
	}

	return nil
}

// calculateRoot calculates the root of the tree branch defined by leaf and
// neighbors.
func (v *Verifier) calculateRoot(neighbors [][]byte, bindex string, leaf []byte) ([]byte, error) {
	// If the leaf is empty, it is a proof of absence.
	if len(leaf) == 0 {
		// Trim the neighbors list.
		neighbors = proofOfAbsenceNeighbors(neighbors)

		// Set the value of the empty leaf
		missingBranchBIndex := bindex[:len(neighbors)]
		leaf = v.hasher.HashEmpty(tree.InvertBitString(missingBranchBIndex))
	}

	// value contains the calculated root so far. It starts from the leaf.
	value := leaf
	for i, neighbor := range neighbors {
		// Get the neighbor bit string index.
		neighborBIndex := tree.NeighborString(bindex[:len(neighbors)-i])
		// If the neighbor is empty, set it to HashEmpty output.
		if len(neighbor) == 0 {
			neighbor = v.hasher.HashEmpty(tree.InvertBitString(neighborBIndex))
		}

		// index is processed starting from len(neighbors)-1 down to 0.
		// If the index bit is 0, then neighbor is on the right,
		// otherwise, neighbor is on the left.
		b := uint8(bindex[len(neighbors)-1-i])
		var left, right []byte
		switch b {
		case tree.Zero:
			left = value
			right = neighbor
		case tree.One:
			left = neighbor
			right = value
		default:
			return nil, errIndexBit
		}
		value = v.hasher.HashChildren(left, right)
	}
	return value, nil
}

// proofOfAbsenceNeighbors trims all the empty values  at the beginning of the
// neighbors list. The returned list is the one used in the proof of absence.
func proofOfAbsenceNeighbors(neighbors [][]byte) [][]byte {
	var i int
	var v []byte
	for i, v = range neighbors {
		if len(v) != 0 {
			break
		}
	}

	// The last value is a special case.
	if i == len(neighbors)-1 && len(neighbors[i]) == 0 {
		return [][]byte{}
	}
	return neighbors[i:]
}
