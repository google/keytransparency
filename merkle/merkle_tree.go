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

// Package merkle implements a time series prefix tree. Each epoch has its own
// prefix tree. By default, each new epoch is equal to the contents of the
// previous epoch.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.
package merkle

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/e2e-key-server/common"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	cm "github.com/google/e2e-key-server/common/merkle"
)

const (
	// maxDepth is the maximum allowable value of depth.
	maxDepth = cm.IndexLen
)

var (
	// zero is the value used to represent 0 in the index bit string.
	zero = byte('0')
	// one is the data used to represent 1 in the index bit string.
	one = byte('1')
)

// Note: index has two representation:
//  (1) string which is a bit string representation (a string of '0' and '1'
//      characters). In this case, the variable name is bindex. Internaly, the
//      merkle tree uses representation (1) for ease of implementation and to
//      avoid converting back and forth between (1) and (2) in the internal tree
//      functions.
//  (2) []byte which is the bytes representation. In this case, the variable
//      name is index. All external tree APIs (exported functions) use
//      represetation (2).

// Note: data, dataHash, and value
//  - data: is the actual data (in []byte) that is stored in the node leaf. All
//    external tree APIs (exported functions) expect to receive data. Currently,
//    data is a marshaled SignedEntryUpdate proto.
//  - dataHash: is the hash of data and is stored in the leaf node structure.
//  - value: is stored in the leaf node structure and can be:
//     - Leaves: H(TreeNonce || LeafIdentifier || depth || index || dataHash)
//     - Empty leaves: H(TreeNonce || EmptyIdentifier || depth || index || nil)
//     - Intermediate nodes: H(left.value || right.value)

// Tree holds internal state for the Merkle Tree.
type Tree struct {
	roots   map[uint64]*node
	current *node      // Current epoch.
	mu      sync.Mutex // Syncronize access to current.
}

type node struct {
	epoch        uint64 // Epoch for this node.
	bindex       string // Location in the tree.
	commitmentTS uint64 // Commitment timestamp for this node.
	depth        int    // Depth of this node. 0 to 256.
	dataHash     []byte // Hash of the data stored in the node.
	value        []byte // Empty for empty subtrees.
	left         *node  // Left node.
	right        *node  // Right node.
}

// New creates and returns a new instance of Tree.
func New() *Tree {
	tree := &Tree{roots: make(map[uint64]*node)}
	// Initialize the tree with epoch 0 root. This is important because v2
	// GetEntry now queries the tree to read the commitment timestamp of the
	// user profile in order to read from the database.
	tree.addRoot(0)
	return tree
}

// BuildExpectedTree builds a partial merkle tree with the path from the given
// leaf node at the given index, up to the root including all path neighbors.
func FromNeighbors(neighbors [][]byte, index []byte, data []byte) (*Tree, error) {
	bindex := bitString(index)

	// Create a partial tree.
	m := New()
	r, err := m.addRoot(0)
	if err != nil {
		return nil, err
	}

	// Add the leaf node to the partial tree.
	if err := r.addLeaf(data, 0, bindex, 0, 0, true); err != nil {
		return nil, err
	}

	// Add all neighbors to the partial tree.
	for i, v := range(neighbors) {
		if got, want := len(v), cm.HashSize; got != want {
			return nil, grpc.Errorf(codes.InvalidArgument, "len(v) = %v, want %v", got, want)
		}

		// index is processed starting from len(neighbors)-1 down to 0.
		indexBit := len(neighbors) - 1 - i
		b := uint8(bindex[indexBit])
		bindexNeighbor := fmt.Sprintf("%v%v", bindex[:indexBit], string(neighbor(b)))
		// Add a neighbor. In this case, index is not of a full length.
		if err := r.addLeaf(v, 0, bindexNeighbor, 0, 0, false); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// AddRoot adds a new root in the specified epoch. If the epoch is greater than
// t.current.epoch + 1, an error is returned.
func (t *Tree) AddRoot(epoch uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	_, err := t.addRoot(epoch)
	return err
}

// AddLeaf adds a leaf node to the tree at a given index and epoch. Leaf nodes
// must be added in chronological order by epoch.
func (t *Tree) AddLeaf(data []byte, epoch uint64, index []byte, commitmentTS uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), cm.IndexLen/8; got != want {
		return grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, err := t.addRoot(epoch)
	if err != nil {
		return err
	}
	return r.addLeaf(data, epoch, bitString(index), commitmentTS, 0, true)
}

// GetLeafCommitmentTimestamp returns a leaf commitment timestamp for a given
// epoch and index.
func (t *Tree) GetLeafCommitmentTimestamp(epoch uint64, index []byte) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), cm.IndexLen/8; got != want {
		return 0, grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, ok := t.roots[epoch]
	if !ok {
		return 0, grpc.Errorf(codes.NotFound, "Epoch does not exist")
	}

	return r.getLeafCommitmentTimestamp(bitString(index), 0)
}

// AuditPath returns a slice containing each node's neighbor from the bottom to
// the top.
func (t *Tree) AuditPath(epoch uint64, index []byte) ([][]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), cm.IndexLen/8; got != want {
		return nil, grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.InvalidArgument, "epoch %v does not exist", epoch)
	}
	return r.auditPath(bitString(index), 0)
}

// GetRootValue returns the value of the root node in a specific epoch.
func (t *Tree) Root(epoch uint64) ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Epoch does not exist")
	}
	return r.value, nil
}

// addRoot will advance the current epoch by copying the previous root.
// addRoot will prevent attempts to create epochs other than the current and
// current + 1 epoch
func (t *Tree) addRoot(epoch uint64) (*node, error) {
	if t.current == nil {
		// Create the first epoch.
		t.roots[epoch] = &node{epoch, "", 0, 0, nil, nil, nil, nil}
		t.current = t.roots[epoch]
		return t.current, nil
	}

	// If root already exists and is in current epoch return it.
	if epoch == t.current.epoch {
		return t.roots[epoch], nil
	}

	if epoch != t.current.epoch + 1 {
		return nil, grpc.Errorf(codes.FailedPrecondition, "epoch = %d, want = %d", epoch, t.current.epoch + 1)
	}

	// Copy the root node from the previous epoch.
	nextEpoch := t.current.epoch + 1
	t.roots[nextEpoch] = &node{epoch, "", 0, 0, nil, nil, t.current.left, t.current.right}
	t.current = t.roots[nextEpoch]
	return t.current, nil
}

// Parent node is responsible for creating children.
// Inserts leafs in the nearest empty sub branch it finds.
func (n *node) addLeaf(data []byte, epoch uint64, bindex string, commitmentTS uint64, depth int, isLeaf bool) error {
	if n.epoch != epoch {
		return grpc.Errorf(codes.Internal, "epoch = %d want %d", epoch, n.epoch)
	}

	// Base case: we found the first empty sub branch.  Park our data here.
	if n.empty() {
		n.setNode(data, bindex, commitmentTS, depth, isLeaf)
		return nil
	}
	// We reached the bottom of the tree and it wasn't empty.
	// Or we found the same node.
	if depth == maxDepth || n.bindex == bindex {
		return grpc.Errorf(codes.AlreadyExists, "")
	}
	if n.leaf() {
		// Push leaf down and convert n into an interior node.
		if err := n.pushDown(); err != nil {
			return err
		}
	}
	// Make sure the interior node is in the current epoch.
	n.createBranch(bindex[:depth+1])
	err := n.child(bindex[depth]).addLeaf(data, epoch, bindex, commitmentTS, depth+1, isLeaf)
	if err != nil {
		return err
	}
	n.hashIntermediateNode() // Recalculate value on the way back up.
	return nil
}

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
	n.child(b).dataHash = n.dataHash
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
		panic(fmt.Sprintf("len(%v)=%v, want %v. n.bindex=%v", bindex, got, want, n.bindex))
	}
	// The new branch must share a common prefix with n.
	if got, want := bindex[:n.depth], n.bindex[:n.depth]; got != want {
		panic(fmt.Sprintf("bindex[:%v]=%v, want %v", len(n.bindex), got, want))
	}
	b := bindex[n.depth]
	switch {
	case n.child(b) == nil:
		// New empty branch.
		n.setChild(b, &node{n.epoch, bindex, n.commitmentTS, n.depth + 1, nil, nil, nil, nil})
	case n.child(b).epoch != n.epoch && n.child(b).leaf():
		// Found leaf in previous epoch. Create empty node.
		n.setChild(b, &node{n.epoch, bindex, n.commitmentTS, n.depth + 1, nil, nil, nil, nil})
	case n.child(b).epoch != n.epoch && !n.child(b).leaf():
		// Found intermediate in previous epoch.
		// Create an intermediate node in current epoch with children
		// pointing to the previous epoch.
		tmp := n.child(b)
		n.setChild(b, &node{n.epoch, bindex, n.commitmentTS, n.depth + 1, nil, tmp.value, tmp.left, tmp.right})
	}
	return n.child(b)
}

func (n *node) getLeafCommitmentTimestamp(bindex string, depth int) (uint64, error) {
	// If n is nil then we reached a nil node that is not at the bottom of
	// the tree.
	if n == nil {
		return 0, grpc.Errorf(codes.NotFound, "Reached bottom of the tree")
	}

	// Base case: if we found a leaf with the same bindex.
	if n.leaf() && n.bindex == bindex {
		return n.commitmentTS, nil
	}

	return n.child(bindex[depth]).getLeafCommitmentTimestamp(bindex, depth+1)
}

func (n *node) auditPath(bindex string, depth int) ([][]byte, error) {
	if depth == maxDepth || n.leaf() {
		return [][]byte{}, nil
	}
	if n.child(bindex[depth]) == nil {
		return nil, grpc.Errorf(codes.NotFound, "")
	}
	deep, err := n.child(bindex[depth]).auditPath(bindex, depth+1)
	if err != nil {
		return nil, err
	}

	b := bindex[depth]
	if nbr := n.child(neighbor(b)); nbr != nil {
		return append(deep, nbr.value), nil
	}
	value := cm.EmptyLeafValue(n.bindex + string(neighbor(b)))
	return append(deep, value), nil
}

func (n *node) leaf() bool {
	return n.left == nil && n.right == nil
}
func (n *node) empty() bool {
	return n.dataHash == nil && n.left == nil && n.right == nil && n.value == nil
}

func (n *node) child(b uint8) *node {
	switch b {
	case zero:
		return n.left
	case one:
		return n.right
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
		return nil
	}
}

func (n *node) setChild(b uint8, child *node) {
	switch b {
	case zero:
		n.left = child
	case one:
		n.right = child
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
	}
}

// neighbor converts Zero into One and visa versa.
func neighbor(b uint8) uint8 {
	switch b {
	case zero:
		return one
	case one:
		return zero
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
		return 0
	}
}

// hashIntermediateNode updates an interior node's value by
// H(left.value || right.value)
func (n *node) hashIntermediateNode() error {
	if n.leaf() {
		return grpc.Errorf(codes.Internal, "Cannot calcluate the intermediate hash of a leaf node")
	}

	// Compute left values.
	var left []byte
	if n.left != nil {
		left = n.left.value
	} else {
		left = cm.EmptyLeafValue(n.bindex + string(zero))
	}

	// Compute right values.
	var right []byte
	if n.right != nil {
		right = n.right.value
	} else {
		right = cm.EmptyLeafValue(n.bindex + string(one))
	}
	n.value = cm.HashIntermediateNode(left, right)
	return nil
}

// updateLeafValue updates a leaf node's value by
// H(TreeNonce || LeafIdentifier || depth || bindex || dataHash )
// TreeNonce, LeafIdentifier, depth, and bindex are fixed-length.
func (n *node) updateLeafValue() {
	n.value = cm.HashLeaf(cm.LeafIdentifier, n.depth, []byte(n.bindex), n.dataHash)
}

// setNode sets the comittment of the leaf node and updates its hash.
func (n *node) setNode(data []byte, bindex string, commitmentTS uint64, depth int, isLeaf bool) {
	n.bindex = bindex
	n.commitmentTS = commitmentTS
	n.depth = depth
	n.left = nil
	n.right = nil
	if isLeaf {
		n.dataHash = common.Hash(data)
		n.updateLeafValue()
	} else {
		n.value = data
	}
}

// bitString converts a byte slice index into a string of Depth '0' or '1'
// characters.
func bitString(index []byte) string {
	i := new(big.Int)
	i.SetString(hex.EncodeToString(index), 16)
	// A 256 character string of bits with leading zeros.
	return fmt.Sprintf("%0256b", i)
}
