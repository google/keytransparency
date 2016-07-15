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

// Package memhist implements a time series prefix tree. Each epoch has its own
// prefix tree. By default, each new epoch is equal to the contents of the
// previous epoch.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.
package memhist

import (
	"log"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse"
)

const (
	maxDepth = sparse.IndexLen
	size     = sparse.HashSize
)

var hasher = sparse.Coniks

// Note: index has two representation:
//  (1) string which is a bit string representation (a string of '0' and '1'
//      characters). In this case, the variable name is bindex. Internaly, the
//      merkle tree uses representation (1) for ease of implementation and to
//      avoid converting back and forth between (1) and (2) in the internal tree
//      functions.
//  (2) []byte which is the bytes representation. In this case, the variable
//      name is index. All external tree APIs (exported functions) use
//      represetation (2).

// Note: data, data, and value
//  - data: is the actual data (in []byte) that is stored in the node leaf. All
//    external tree APIs (exported functions) expect to receive data. Currently,
//    data is a marshaled SignedEntryUpdate proto.
//  - data: is the hash of data and is stored in the leaf node structure.
//  - value: is stored in the leaf node structure and can be:
//     - Leaves: H(LeafIdentifier || depth || index || data)
//     - Empty leaves: H(EmptyIdentifier || depth || index || nil)
//     - Intermediate nodes: H(left.value || right.value)

// Tree holds internal state for the SparseMerkle Tree. Not thread safe.
type Tree struct {
	roots   map[int64]*node
	pending map[[size]byte][]byte
	current int64
}

type node struct {
	epoch  int64  // Epoch for this node.
	bindex string // Location in the tree.
	depth  int    // Depth of this node. 0 to 256.
	data   []byte // Data stored in the node.
	value  []byte // Empty for empty subtrees.
	left   *node  // Left node.
	right  *node  // Right node.
}

// New creates and returns a new instance of Tree.
func New() *Tree {
	t := &Tree{
		roots:   make(map[int64]*node),
		pending: make(map[[size]byte][]byte),
	}

	// Create the first epoch with a single empty leaf to distinguish between
	// empty tree and empty branch.
	t.roots[0] = &node{
		value: hashEmpty(""),
	}
	return t
}

// QueueLeaf queues a leaf to be written on the next Commit().
func (t *Tree) QueueLeaf(ctx context.Context, index, leaf []byte) error {
	log.Printf("QueueLeaf(%v, %v)", index, leaf)
	if got, want := len(index), size; got != want {
		return grpc.Errorf(codes.InvalidArgument, "len(%v)=%v, want %v", index, got, want)
	}
	var v [size]byte
	copy(v[:], index)
	t.pending[v] = leaf
	return nil
}

// Commit takes all the Queued values since the last Commmit() and writes them.
// Commit is NOT multi-process safe. It should only be called from the sequencer.
func (t *Tree) Commit() (int64, error) {
	for k, v := range t.pending {
		if err := t.SetNodeAt(nil, k[:], maxDepth, v, t.current); err != nil {
			log.Fatalf("Failed to set node: %v", err)
		}
	}
	t.pending = make(map[[size]byte][]byte) // Clear pending leafs.

	// Create the next epoch.
	t.roots[t.current+1] = t.roots[t.current]
	this := t.current
	t.current++
	log.Printf("Commit()=%v", this)
	return this, nil
}

// ReadRootAt returns the value of the root node in a specific epoch.
func (t *Tree) ReadRootAt(ctx context.Context, epoch int64) ([]byte, error) {
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Epoch %v not found", epoch)
	}
	return r.value, nil
}

// ReadLeafAt returns the leaf value at epoch.
func (t *Tree) ReadLeafAt(ctx context.Context, index []byte, epoch int64) ([]byte, error) {
	bindex := tree.BitString(index)
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Epoch %v not found", epoch)
	}

	// Walk the tree to the leaf node.
	cnt := r
	for i := 0; i < maxDepth; i++ {
		if cnt.leaf() {
			break
		}
		cnt = cnt.child(bindex[i])
	}
	return cnt.data, nil
}

// NeighborsAt returns the list of neighbors from the neighbor leaf to just below the root at epoch.
func (t *Tree) NeighborsAt(ctx context.Context, index []byte, epoch int64) ([][]byte, error) {
	bindex := tree.BitString(index)
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Epoch %v not found", epoch)
	}

	// Walk the tree to the leaf node.
	neighbors := make([][]byte, 0, maxDepth)
	cnt := r
	for i := 0; i < maxDepth && cnt != nil && !cnt.leaf(); i++ {
		b := bindex[i]
		if nbr := cnt.child(tree.Neighbor(b)); nbr != nil {
			neighbors = append(neighbors, nbr.value)
		} else {
			neighbors = append(neighbors, hashEmpty(tree.NeighborString(bindex[:i+1])))
		}
		cnt = cnt.child(b)
	}
	return neighbors, nil
}

// ReadLeafAt returns the leaf value at epoch.
func (t *Tree) readNodeAt(ctx context.Context, index []byte, depth int, epoch int64) ([]byte, error) {
	bindex := tree.BitString(index)
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Epoch %v not found", epoch)
	}

	// Walk the tree to the leaf node.
	cnt := r
	i := 0
	for ; i < depth; i++ {
		if cnt.leaf() {
			break
		}
		cnt = cnt.child(bindex[i])
	}
	if cnt == nil {
		return hashEmpty(bindex[:i]), nil
	}
	return cnt.value, nil
}

// SetNodeAt sets intermediate and leaf node values directly at epoch.
func (t *Tree) SetNodeAt(ctx context.Context, index []byte, depth int, value []byte, epoch int64) error {
	bindex := tree.BitString(index)[:depth]

	isLeaf := depth == maxDepth
	if depth > maxDepth {
		return grpc.Errorf(codes.InvalidArgument, "depth %v > %v", depth, maxDepth)
	}
	root, ok := t.roots[epoch]
	if !ok {
		return grpc.Errorf(codes.NotFound, "")
	}

	dirty := make([]*node, maxDepth) // Breadth first.
	cnt := root
	i := 0
	// Create the path to the node.
	for ; i < depth && !cnt.empty() && cnt.bindex != bindex; i++ {
		dirty[i] = cnt
		if cnt.leaf() {
			cnt.pushDown()
		}
		cnt.createBranch(bindex[:i+1])
		cnt = cnt.child(bindex[i])
	}
	cnt.setNode(value, bindex, i, isLeaf)
	// Recalculate intermediate hashes.
	for i--; i >= 0; i-- {
		dirty[i].hashIntermediateNode()
	}
	return nil
}

//
// Private methods
//

// pushDown takes a leaf node and pushes it one level down in the prefix tree,
// converting this node into an interior node.  This function does NOT update
// n.value.
func (n *node) pushDown() error {
	if !n.leaf() {
		return grpc.Errorf(codes.Internal, "Cannot push down interor node")
	}
	if n.depth == maxDepth {
		return grpc.Errorf(codes.Internal, "Leaf is already at max depth")
	}

	// Create a sub branch and copy this node.
	b := n.bindex[n.depth]
	n.createBranch(n.bindex)
	n.child(b).data = n.data
	// Whenever a node is pushed down, its value must be recalculated.
	n.child(b).updateLeafValue()

	n.bindex = n.bindex[:n.depth] // Convert into an interior node.
	return nil
}

// createBranch takes care of copy-on-write semantics. Creates and returns a
// valid child node along branch b. Does not copy leaf nodes.
// index must share its previous with n.bindex
func (n *node) createBranch(bindex string) *node {
	// New branch must have a longer index than n.
	if got, want := len(bindex), n.depth+1; got < want {
		log.Fatalf("len(%v)=%v, want %v. n.bindex=%v", bindex, got, want, n.bindex)
	}
	// The new branch must share a common prefix with n.
	if got, want := bindex[:n.depth], n.bindex[:n.depth]; got != want {
		log.Fatalf("bindex[:%v]=%v, want %v", len(n.bindex), got, want)
	}
	b := bindex[n.depth]
	switch {
	case n.child(b) == nil:
		// New empty branch.
		n.setChild(b, &node{n.epoch, bindex, n.depth + 1, nil, nil, nil, nil})
	case n.child(b).epoch != n.epoch && n.child(b).leaf():
		// Found leaf in previous epoch. Create empty node.
		n.setChild(b, &node{n.epoch, bindex, n.depth + 1, nil, nil, nil, nil})
	case n.child(b).epoch != n.epoch && !n.child(b).leaf():
		// Found intermediate in previous epoch.
		// Create an intermediate node in current epoch with children
		// pointing to the previous epoch.
		tmp := n.child(b)
		n.setChild(b, &node{n.epoch, bindex, n.depth + 1, nil, tmp.value, tmp.left, tmp.right})
	}
	return n.child(b)
}

func (n *node) leaf() bool {
	return n.left == nil && n.right == nil
}

// empty returns if a node is empty. A node is empty if its data and
// children pointers are nil. The node value should not be considered as
// a part of the empty test because an empty tree has an empty root with
// an empty leaf value.
func (n *node) empty() bool {
	return n.data == nil && n.left == nil && n.right == nil
}

func (n *node) child(b uint8) *node {
	switch b {
	case tree.Zero:
		return n.left
	case tree.One:
		return n.right
	default:
		log.Fatalf("Invalid bit %v", b)
		return nil
	}
}

func (n *node) setChild(b uint8, child *node) {
	switch b {
	case tree.Zero:
		n.left = child
	case tree.One:
		n.right = child
	default:
		log.Fatalf("Invalid bit %v", b)
	}
}

// hashIntermediateNode updates an interior node's value by
// H(left.value || right.value)
func (n *node) hashIntermediateNode() {
	if n.leaf() {
		log.Fatalf("Cannot calcluate the intermediate hash of a leaf node")
	}

	// Compute left values.
	var left []byte
	if n.left != nil {
		left = n.left.value
	} else {
		left = hashEmpty(n.bindex + string(tree.Zero))
	}

	// Compute right values.
	var right []byte
	if n.right != nil {
		right = n.right.value
	} else {
		right = hashEmpty(n.bindex + string(tree.One))
	}
	n.value = hasher.HashChildren(left, right)
}

// updateLeafValue updates a leaf node's value by
// H(LeafIdentifier || depth || bindex || data), where LeafIdentifier,
// depth, and bindex are fixed-length.
func (n *node) updateLeafValue() {
	n.value = hasher.HashLeaf([]byte(n.bindex), n.depth, n.data)
}

// setNode sets the comittment of the leaf node and updates its hash.
func (n *node) setNode(data []byte, bindex string, depth int, isLeaf bool) {
	if depth < 0 {
		panic("setNode with negative index")
	}
	n.bindex = bindex
	n.depth = depth
	n.left = nil
	n.right = nil
	if isLeaf {
		n.data = data
		n.updateLeafValue()
	} else {
		n.value = data
	}
}

func hashEmpty(bindex string) []byte {
	return hasher.HashEmpty(tree.InvertBitString(bindex))
}
