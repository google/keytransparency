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

// Package verifier allows client to verify a tree proof.
package verifier

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/google/key-transparency/core/tree"
	"github.com/google/key-transparency/core/tree/sparse"
)

var (
	// ErrNeighborsLen occurs when the neighbor list length is longer than
	// the maximum allowed value.
	ErrNeighborsLen = fmt.Errorf("Neighbors len > %d", sparse.IndexLen)
	// ErrIndexBit occurs when the string-formatted index contains an invalid
	// bit (character), i.e., other than '0' or '1'.
	ErrIndexBit = errors.New("Invalid index bit")
	// ErrInvalidProof occurs when the provided tree proof cannot be
	// verified. This can be caused by an invalid neighbor tree or root.
	ErrInvalidProof = errors.New("Invalid proof")
)

// Verifier represents a sparse tree proof verifier object.
type Verifier struct {
	hasher sparse.TreeHasher
}

// New returns a new tree proofs verifier object.
func New(hasher sparse.TreeHasher) *Verifier {
	return &Verifier{hasher}
}

// VerifyProof verifies a tree proof of a given leaf at a given index based on
// the provided root and neighbor list
func (v *Verifier) VerifyProof(neighbors [][]byte, index, leaf, root []byte) error {
	if len(neighbors) > sparse.IndexLen {
		return ErrNeighborsLen
	}

	// Calculate the tree root based on neighbors and leaf.
	calculatedRoot, err := v.calculateRoot(neighbors, tree.BitString(index), leaf)
	if err != nil {
		return err
	}

	// Verify that calculated and provided roots match.
	if !bytes.Equal(calculatedRoot, root) {
		return ErrInvalidProof
	}

	return nil
}

// calculateRoot calculates the root of the tree branch defined by leaf and
// neighbors.
func (v *Verifier) calculateRoot(neighbors [][]byte, bindex string, leaf []byte) ([]byte, error) {
	// If the leaf is empty, it is a proof of absence.
	if len(leaf) == 0 {
		// Trim the neighbors list.
		neighbors = trimNeighbors(neighbors)

		// Set the value of the empty leaf
		missingBranchBIndex := bindex[:len(neighbors)]
		leaf = v.hasher.HashEmpty(tree.InvertBitString(missingBranchBIndex))
	}

	// calculatedRoot contains the calculated root so far. It starts from the leaf.
	calculatedRoot := leaf
	for i, neighbor := range neighbors {
		// Get the neighbor bit string index.
		neighborBIndex := tree.NeighborString(bindex[:len(neighbors)-i])
		// If the neighbor is empty, set it to HashEmpty output.
		if len(neighbor) == 0 {
			neighbor = v.hasher.HashEmpty(tree.InvertBitString(neighborBIndex))
		}

		// The leaf index is processed starting from len(neighbors)-1
		// down to 0. If the index bit is 0, then neighbor is on the
		// right, otherwise, neighbor is on the left.
		switch bindex[len(neighbors)-1-i] {
		case tree.Zero:
			calculatedRoot = v.hasher.HashChildren(calculatedRoot, neighbor)
		case tree.One:
			calculatedRoot = v.hasher.HashChildren(neighbor, calculatedRoot)
		default:
			return nil, ErrIndexBit
		}
	}
	return calculatedRoot, nil
}

// trimNeighbors trims all the empty values at the beginning of the neighbors
// list. The returned list is the one used in the proof of absence.
func trimNeighbors(neighbors [][]byte) [][]byte {
	for i, v := range neighbors {
		if len(v) != 0 {
			return neighbors[i:]
		}
	}
	return [][]byte{}
}
