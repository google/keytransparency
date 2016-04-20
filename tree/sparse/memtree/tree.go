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

// Package memtree implements a sparse prefix tree.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.
package memtree

import (
	"golang.org/x/net/context"

	"github.com/google/e2e-key-server/tree/sparse/memhist"
)

// Tree holds internal state for the sparse merkle tree. Not thread-safe.
type Tree struct {
	tree  *memhist.Tree
	epoch int64
}

// New creates and returns a new instance of Tree.
func New() *Tree {
	return &Tree{memhist.New(), 0}
}

func (t *Tree) ReadRoot(ctx context.Context) ([]byte, error) {
	return t.tree.ReadRootAt(ctx, t.epoch)
}

// ReadLeaf returns the current value of the leaf node.
func (t *Tree) ReadLeaf(ctx context.Context, index []byte) ([]byte, error) {
	return t.tree.ReadLeafAt(ctx, index, t.epoch)
}

// WriteLeaf writes a leaf node and updates the root.
func (t *Tree) WriteLeaf(ctx context.Context, index, leaf []byte) error {
	if err := t.tree.QueueLeaf(ctx, index, leaf); err != nil {
		return err
	}
	epoch, err := t.tree.Commit()
	if err != nil {
		return err
	}
	t.epoch = epoch
	return nil
}

// Neighbors returns the current list of neighbors from the neighbor leaf to just below the root.
func (t *Tree) Neighbors(ctx context.Context, index []byte) ([][]byte, error) {
	return t.tree.NeighborsAt(ctx, index, t.epoch)
}

// SetNodeAt sets intermediate and leaf node values directly.
func (t *Tree) SetNode(ctx context.Context, index []byte, depth int, value []byte) error {
	return t.tree.SetNodeAt(ctx, index, depth, value, t.epoch)
}
