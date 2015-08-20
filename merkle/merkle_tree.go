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
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	// IndexLen is the maximum number of levels in this Merkle Tree.
	IndexLen = sha256.Size * 8
	// maxDepth is the maximum allowable value of depth.
	maxDepth = IndexLen
	// HashBytes is the number of bytes in each node's value.
	HashBytes = sha256.Size
)

var (
	// TreeNonce is a constant value used as a salt in all leaf node calculations.
	// The TreeNonce prevents different realms from producing collisions.
	TreeNonce = []byte{241, 71, 100, 55, 62, 119, 69, 16, 150, 179, 228, 81, 34, 200, 144, 6}
	// LeafIdentifier is the value used to indicate a leaf node.
	LeafIdentifier = []byte("L")
	// EmptyIdentifier is used while calculating the value of nil sub branches.
	EmptyIdentifier = []byte("E")
	// Zero is the value used to represent 0 in the index bit string.
	Zero = byte('0')
	// One is the value used to represent 1 in the index bit string.
	One = byte('1')
)

// Tree holds internal state for the Merkle Tree.
type Tree struct {
	roots   map[uint64]*node
	current *node      // Current epoch.
	mu      sync.Mutex // Syncronize access to current.
}

type node struct {
	epoch        uint64               // Epoch for this node.
	index        string                     // Location in the tree.
	commitmentTS uint64 // Commitment timestamp for this node.
	depth        int                        // Depth of this node. 0 to 256.
	value        []byte                     // Empty for empty subtrees.
	left         *node                      // Left node.
	right        *node                      // Right node.
}

// New creates and returns a new instance of Tree.
func New() *Tree {
	return &Tree{roots: make(map[uint64]*node)}
}

// AddLeaf adds a leaf node to the tree at a given index and epoch. Leaf nodes
// must be added in chronological order by epoch.
func (t *Tree) AddLeaf(value []byte, epoch uint64, index string, commitmentTS uint64) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), IndexLen/4; got != want {
		return grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, err := t.addRoot(epoch)
	if err != nil {
		return err
	}
	return r.addLeaf(value, epoch, BitString(index), commitmentTS, 0)
}

// GetLeafCommitmentTimestamp returns a leaf commitment timestamp for a given
// epoch and index.
func (t *Tree) GetLeafCommitmentTimestamp(epoch uint64, index string) (uint64, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), IndexLen/4; got != want {
		return 0, grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, ok := t.roots[epoch]
	if !ok {
		return 0, grpc.Errorf(codes.NotFound, "Epoch does not exist")
	}

	return r.getLeafCommitmentTimestamp(BitString(index), 0)
}

// AuditPath returns a slice containing the value of the leaf node followed by
// each node's neighbor from the bottom to the top.
func (t *Tree) AuditPath(epoch uint64, index string) ([][]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if got, want := len(index), IndexLen/4; got != want {
		return nil, grpc.Errorf(codes.InvalidArgument, "len(index) = %v, want %v", got, want)
	}
	r, ok := t.roots[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.InvalidArgument, "epoch %v does not exist", epoch)
	}
	return r.auditPath(BitString(index), 0)
}

// BitString converts a hex prefix into a string of Depth '0' or '1' characters.
func BitString(index string) string {
	i := new(big.Int)
	i.SetString(index, 16)
	// A 256 character string of bits with leading zeros.
	return fmt.Sprintf("%0256b", i)
}

// addRoot will advance the current epoch by copying the previous root.
// addRoot will prevent attempts to create epochs other than the current and
// current + 1 epoch
func (t *Tree) addRoot(epoch uint64) (*node, error) {
	if t.current == nil {
		// Create the first epoch.
		t.roots[epoch] = &node{epoch, "", 0, 0, nil, nil, nil}
		t.current = t.roots[epoch]
		return t.current, nil
	}
	if epoch < t.current.epoch {
		return nil, grpc.Errorf(codes.FailedPrecondition, "epoch = %d, want >= %d", epoch, t.current.epoch)
	}

	for t.current.epoch < epoch {
		// Copy the root node from the previous epoch.
		nextEpoch := t.current.epoch + 1
		t.roots[nextEpoch] = &node{epoch, "", 0, 0, nil, t.current.left, t.current.right}
		t.current = t.roots[nextEpoch]
	}
	return t.current, nil
}

// Parent node is responsible for creating children.
// Inserts leafs in the nearest empty sub branch it finds.
func (n *node) addLeaf(value []byte, epoch uint64, index string, commitmentTS uint64, depth int) error {
	if n.epoch != epoch {
		return grpc.Errorf(codes.Internal, "epoch = %d want %d", epoch, n.epoch)
	}

	// Base case: we found the first empty sub branch.  Park our value here.
	if n.empty() {
		n.setLeaf(value, index, commitmentTS, depth)
		return nil
	}
	// We reached the bottom of the tree and it wasn't empty.
	// Or we found the same node.
	if depth == maxDepth || n.index == index {
		return grpc.Errorf(codes.AlreadyExists, "")
	}
	if n.leaf() {
		// Push leaf down and convert n into an interior node.
		if err := n.pushDown(); err != nil {
			return err
		}
	}
	// Make sure the interior node is in the current epoch.
	n.createBranch(index[:depth+1])
	err := n.child(index[depth]).addLeaf(value, epoch, index, commitmentTS, depth+1)
	if err != nil {
		return err
	}
	n.hashIntermediateNode() // Recalculate value on the way back up.
	return nil
}

// pushDown takes a leaf node and pushes it one level down in the prefix tree,
// converting this node into an interior node.  This function does NOT update
// n.value
func (n *node) pushDown() error {
	if !n.leaf() {
		return grpc.Errorf(codes.Internal, "Cannot push down interor node")
	}
	if n.depth == maxDepth {
		return grpc.Errorf(codes.Internal, "Leaf is already at max depth")
	}

	// Create a sub branch and copy this node.
	b := n.index[n.depth]
	n.createBranch(n.index)
	n.child(b).value = n.value
	n.index = n.index[:n.depth] // Convert into an interior node.
	return nil
}

// createBranch takes care of copy-on-write semantics. Creates and returns a
// valid child node along branch b. Does not copy leaf nodes.
// index must share its previous with n.index
func (n *node) createBranch(index string) *node {
	// New branch must have a longer index than n.
	if got, want := len(index), n.depth+1; got < want {
		panic(fmt.Sprintf("len(%v)=%v, want %v. n.index=%v", index, got, want, n.index))
	}
	// The new branch must share a common prefix with n.
	if got, want := index[:n.depth], n.index[:n.depth]; got != want {
		panic(fmt.Sprintf("index[:%v]=%v, want %v", len(n.index), got, want))
	}
	b := index[n.depth]
	switch {
	case n.child(b) == nil:
		// New empty branch.
		n.setChild(b, &node{n.epoch, index, n.commitmentTS, n.depth + 1, nil, nil, nil})
	case n.child(b).epoch != n.epoch && n.child(b).leaf():
		// Found leaf in previous epoch. Create empty node.
		n.setChild(b, &node{n.epoch, index, n.commitmentTS, n.depth + 1, nil, nil, nil})
	case n.child(b).epoch != n.epoch && !n.child(b).leaf():
		// Found intermediate in previous epoch.
		// Create an intermediate node in current epoch with children
		// pointing to the previous epoch.
		tmp := n.child(b)
		n.setChild(b, &node{n.epoch, index, n.commitmentTS, n.depth + 1, tmp.value, tmp.left, tmp.right})
	}
	return n.child(b)
}

func (n *node) getLeafCommitmentTimestamp(index string, depth int) (uint64, error) {
	// If n is nil then we reached a nil node that is not at the bottom of
	// the tree.
	if n == nil {
		return 0, grpc.Errorf(codes.NotFound, "Reached bottom of the tree")
	}

	// Base case: if we found a leaf with the same index
	if n.leaf() && n.index == index {
		return n.commitmentTS, nil
	}

	return n.child(index[depth]).getLeafCommitmentTimestamp(index, depth+1)
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
	return append(deep, EmptyValue(n.index+string(neighbor(b)))), nil
}

func (n *node) leaf() bool {
	return n.left == nil && n.right == nil
}
func (n *node) empty() bool {
	return n.left == nil && n.right == nil && n.value == nil
}

func (n *node) child(b uint8) *node {
	switch b {
	case Zero:
		return n.left
	case One:
		return n.right
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
		return nil
	}
}

func (n *node) setChild(b uint8, value *node) {
	switch b {
	case Zero:
		n.left = value
	case One:
		n.right = value
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
	}
}

// neighbor converts Zero into One and visa versa.
func neighbor(b uint8) uint8 {
	switch b {
	case Zero:
		return One
	case One:
		return Zero
	default:
		panic(fmt.Sprintf("invalid bit %v", b))
		return 0
	}
}

// hashIntermediateNode updates an interior node's value by H(left || right)
func (n *node) hashIntermediateNode() {
	if n.leaf() {
		return
	}
	h := sha256.New()

	if n.left != nil {
		h.Write(n.left.value)
	} else {
		h.Write(EmptyValue(n.index + string(Zero)))
	}
	if n.right != nil {
		h.Write(n.right.value)
	} else {
		h.Write(EmptyValue(n.index + string(One)))
	}
	n.value = h.Sum(nil)
}

// hashLeaf updates a leaf node's value by
// H(TreeNonce || LeafIdentifier || depth || index || value )
// TreeNonce, LeafIdentifier, depth, and index are fixed-length.
func (n *node) hashLeaf(value []byte) {
	depth := make([]byte, 4)
	binary.BigEndian.PutUint32(depth, uint32(n.depth))

	h := sha256.New()
	h.Write(TreeNonce[:])
	h.Write(LeafIdentifier)
	h.Write(depth)
	h.Write([]byte(n.index))
	h.Write(value)
	n.value = h.Sum(nil)
}

// setLeaf sets the comittment of the leaf node and updates its hash.
func (n *node) setLeaf(value []byte, index string, commitmentTS uint64, depth int) {
	n.index = index
	n.commitmentTS = commitmentTS
	n.depth = depth
	n.left = nil
	n.right = nil
	n.hashLeaf(value)
}

// EmptyValue computes the value of an empty leaf as
// H(TreeNonce || EmptyIdentifier || depth || index).
// TreeNonce, EmptyIdentifier, depth, and index are fixed-length.
func EmptyValue(prefix string) []byte {
	depth := make([]byte, 4)
	binary.BigEndian.PutUint32(depth, uint32(len(prefix)))

	h := sha256.New()
	h.Write(TreeNonce[:])
	h.Write(EmptyIdentifier)
	h.Write(depth)
	h.Write([]byte(prefix))
	s := h.Sum(nil)
	return s
}
