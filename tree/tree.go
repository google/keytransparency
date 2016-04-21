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

// package tree contains functions for manipulating generic tree representations.
package tree

import (
	"golang.org/x/net/context"
)

// SparseFactory creates a Sparse Tree from a set of neighbor nodes for testing.
type SparseFactory interface {
	// FromNeighbors builds a sparse merkle tree with the path from the given leaf
	// node at the given index, up to the root including all path neighbors.
	FromNeighbors(neighbors [][]byte, index, leaf []byte) Sparse
}

// Sparse is a sparse merkle tree.
type Sparse interface {
	// ReadRoot returns the current value of the root hash.
	ReadRoot(ctx context.Context) ([]byte, error)
	// ReadLeaf returns the current value of the leaf node.
	ReadLeaf(ctx context.Context, index []byte) ([]byte, error)
	// WriteLeaf writes a leaf node and updates the root.
	WriteLeaf(ctx context.Context, index, leaf []byte) error
	// Neighbors returns the current list of neighbors from the neighbor leaf to just below the root.
	Neighbors(ctx context.Context, index []byte) ([][]byte, error)
}

// SparseHist is a temporal sparse merkle tree.
type SparseHist interface {
	// QueueLeaf queues a leaf to be written on the next Commit().
	QueueLeaf(ctx context.Context, index, leaf []byte) error
	// Commit takes all the Queued values since the last Commmit() and writes them.
	// Commit is NOT multi-process safe. It should only be called from the sequencer.
	Commit() (epoch int64, err error)
	// ReadRootAt returns the root value at epoch.
	ReadRootAt(ctx context.Context, epoch int64) ([]byte, error)
	// ReadLeafAt returns the leaf value at epoch.
	ReadLeafAt(ctx context.Context, index []byte, epoch int64) ([]byte, error)
	// Neighbors returns the list of neighbors from the neighbor leaf to just below the root at epoch.
	NeighborsAt(ctx context.Context, index []byte, epoch int64) ([][]byte, error)
}
