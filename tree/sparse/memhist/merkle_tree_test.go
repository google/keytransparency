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

package memhist

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/net/context"

	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse"
)

const (
	testCommitmentTimestamp = 1
)

var (
	AllZeros     = strings.Repeat("0", 256/4)
	ctx          = context.Background()
	defaultIndex = []string{
		"8000000000000000000000000000000000000000000000000000000000000001",
		"C000000000000000000000000000000000000000000000000000000000000001",
	}
)

func DefaultTree(t *testing.T) *Tree {
	// Construct a tree of the following form:
	//     r
	//    e  a
	//      3  4
	m := New()
	leafs := []struct {
		hindex string
		value  string
	}{
		{defaultIndex[0], "3"},
		{defaultIndex[1], "4"},
	}
	for _, l := range leafs {
		value := []byte(l.value)
		if err := m.QueueLeaf(ctx, H2B(l.hindex), value); err != nil {
			t.Fatalf("QueueLeaf(%v)=%v", l.hindex, err)
		}
	}
	if epoch, err := m.Commit(); err != nil || epoch != 0 {
		t.Fatalf("Commit()=%v, %v, want %v, <nil>", epoch, err, 0)
	}
	return m
}

// TestQueueCommitRead ensures that saved data is returned.
func TestQueueCommitRead(t *testing.T) {
	m := New()
	leafs := []struct {
		hindex string
	}{
		{"0000000000000000000000000000000000000000000000000000000000000000"},
		{"F000000000000000000000000000000000000000000000000000000000000000"},
		{"2000000000000000000000000000000000000000000000000000000000000000"},
		{"C000000000000000000000000000000000000000000000000000000000000000"},
	}
	for i, test := range leafs {
		data := []byte{byte(i)}
		index := H2B(test.hindex)
		if err := m.QueueLeaf(ctx, index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v)", test.hindex, data, err)
		}
		epoch, err := m.Commit()
		if err != nil {
			t.Errorf("Commit()=%v, %v, want %v, nil", epoch, err)
		}
		readData, err := m.ReadLeafAt(ctx, index, epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, index, err)
		}
		if got, want := readData, data; !bytes.Equal(got, want) {
			t.Errorf("ReadLeafAt(%v, %v)=%v, want %v", epoch, index, got, want)
		}
	}
}

// TestCommit verifies that the epoch advancement preserves tree shape.
func TestCommit(t *testing.T) {
	m := DefaultTree(t)
	m.Commit()
	epoch, err := m.Commit()
	if err != nil {
		t.Errorf("Commit failed: %v", err)
	}
	tests := []struct {
		hindex string
		depth  int
	}{
		{AllZeros, 1},
		{defaultIndex[0], 2},
		{defaultIndex[1], 2},
	}
	for _, test := range tests {
		nbrs, _ := m.NeighborsAt(ctx, H2B(test.hindex), epoch)
		if got, want := len(nbrs), test.depth; got != want {
			t.Errorf("len(NeighborsAt(%v))=%v, want %v", test.hindex, got, want)
		}
	}
}

func TestReadLeafNodesAt(t *testing.T) {
	m := DefaultTree(t)
	leafs := []struct {
		hindex string
		depth  int
		value  string
		hash   []byte
	}{
		{AllZeros, 1, "", nil},
		{defaultIndex[0], 2, "3", nil},
		{defaultIndex[1], 2, "4", nil},
	}
	for _, l := range leafs {
		bindex := tree.BitString(H2B(l.hindex))
		if l.value != "" {
			data := []byte(l.value)
			l.hash = sparse.HashLeaf(true, l.depth, []byte(bindex), data)
		} else {
			l.hash = sparse.EmptyLeafValue(bindex[:l.depth])
		}

		got, err := m.readNodeAt(nil, H2B(l.hindex), l.depth, 0)
		if err != nil {
			t.Errorf("readNodeAt(%v)=%v", l.hindex, err)
		}
		if want := l.hash; !bytes.Equal(got, want) {
			t.Errorf("readNodeAt(%v)=%v, want %v", l.hindex, got, want)
		}
	}
}

func TestReadIntermediateNodesAt(t *testing.T) {
	m := DefaultTree(t)
	leafs := []struct {
		hindex string
		depth  int
		value  string
		hash   []byte
	}{
		{AllZeros, 1, "", nil},
		{defaultIndex[0], 2, "3", nil},
		{defaultIndex[1], 2, "4", nil},
	}
	for i, l := range leafs {
		bindex := tree.BitString(H2B(l.hindex))
		if l.value != "" {
			data := []byte(l.value)
			leafs[i].hash = sparse.HashLeaf(true, l.depth, []byte(bindex), data)
		} else {
			leafs[i].hash = sparse.EmptyLeafValue(bindex[:l.depth])
		}
	}
	interior := []struct {
		hindex string
		depth  int
		hash   []byte
	}{
		{defaultIndex[0], 1, sparse.HashIntermediateNode(leafs[1].hash, leafs[2].hash)},
	}
	for _, l := range interior {
		got, err := m.readNodeAt(nil, H2B(l.hindex), l.depth, 0)
		if err != nil {
			t.Errorf("readNodeAt(%v, %v)=%v", l.hindex, l.depth, err)
		}
		if want := l.hash; !bytes.Equal(got, want) {
			t.Errorf("readNodeAt(%v, %v)=%v, want %v", l.hindex, l.depth, got, want)
		}
	}
}

func TestReadRootAt(t *testing.T) {
	m := DefaultTree(t)
	// Compute expected root:
	// r := h(empty, h(1, 2)

	leafs := []struct {
		hindex string
		depth  int
		value  string
		hash   []byte
	}{
		{AllZeros, 1, "", nil},
		{defaultIndex[0], 2, "3", nil},
		{defaultIndex[1], 2, "4", nil},
	}
	for i, l := range leafs {
		bindex := tree.BitString(H2B(l.hindex))
		if l.value != "" {
			data := []byte(l.value)
			leafs[i].hash = sparse.HashLeaf(true, l.depth, []byte(bindex), data)
		} else {
			leafs[i].hash = sparse.EmptyLeafValue(bindex[:l.depth])
		}
	}
	interior := []struct {
		depth  int
		hindex string
		hash   []byte
	}{
		{1, defaultIndex[0], sparse.HashIntermediateNode(leafs[1].hash, leafs[2].hash)},
	}
	root := []struct {
		value []byte
	}{
		{sparse.HashIntermediateNode(leafs[0].hash, interior[0].hash)},
	}
	for _, l := range root {
		got, err := m.ReadRootAt(ctx, 0)
		if err != nil {
			t.Errorf("readRootAt()=%v", err)
		}
		if want := l.value; !bytes.Equal(got, want) {
			t.Errorf("readRootAt()=%v, want %v", got, want)
		}
	}
}

func TestReadRootNotFound(t *testing.T) {
	m := DefaultTree(t)
	tests := []struct {
		epoch int64
		err   bool
	}{
		{0, false},
		{1, false},
		{5, true},
	}

	for _, test := range tests {
		_, err := m.ReadRootAt(ctx, test.epoch)
		if got, want := err != nil, test.err; got != want {
			t.Errorf("ReadRootAt(%v)=%v, want %v", test.epoch, got, want)
		}
	}
}

func TestNeighborDepth(t *testing.T) {
	m := DefaultTree(t)
	m2 := New()
	m2.QueueLeaf(nil, H2B(defaultIndex[0]), []byte("0"))
	m2.Commit()
	tests := []struct {
		t      *Tree
		hindex string
		depth  int
	}{
		{m, AllZeros, 1},        // Proof of absence.
		{m, defaultIndex[0], 2}, // Proof of presence.
		{m, defaultIndex[1], 2},
		{m2, defaultIndex[0], 0},
	}
	for _, test := range tests {
		nbrs, _ := test.t.NeighborsAt(ctx, H2B(test.hindex), 0)
		if got, want := len(nbrs), test.depth; got != want {
			t.Errorf("len(NeighborsAt(%v))=%v, want %v", test.hindex, got, want)
		}
	}
}

func TestNeighborsAt(t *testing.T) {
	m := DefaultTree(t)
	leafs := []struct {
		hindex string
		depth  int
		value  string
		hash   []byte
	}{
		{AllZeros, 1, "", nil},
		{defaultIndex[0], 2, "3", nil},
		{defaultIndex[1], 2, "4", nil},
	}
	for i, l := range leafs {
		bindex := tree.BitString(H2B(l.hindex))
		if l.value != "" {
			data := []byte(l.value)
			leafs[i].hash = sparse.HashLeaf(true, l.depth, []byte(bindex), data)
		} else {
			leafs[i].hash = sparse.EmptyLeafValue(bindex[:l.depth])
		}
	}
	tests := []struct {
		hindex    string
		neighbors [][]byte
	}{
		{defaultIndex[0], [][]byte{leafs[0].hash, leafs[2].hash}}, // 3
		{defaultIndex[1], [][]byte{leafs[0].hash, leafs[1].hash}}, // 4
	}
	for _, tt := range tests {
		index := H2B(tt.hindex)
		nbrs, _ := m.NeighborsAt(ctx, index, 0)
		if got, want := nbrs, tt.neighbors; !reflect.DeepEqual(got, want) {
			t.Errorf("NeighborsAt(%v)=\n%v, want \n%v", tt.hindex, got, want)
		}
	}

}

func TestPushDown(t *testing.T) {
	n := &node{bindex: tree.BitString(H2B(AllZeros))}
	if !n.leaf() {
		t.Errorf("node without children was a leaf")
	}
	n.pushDown()
	if n.leaf() {
		t.Errorf("node was still a leaf after push")
	}
	if !n.left.leaf() {
		t.Errorf("new child was not a leaf after push")
	}
}

func TestCreateBranch(t *testing.T) {
	n := &node{bindex: tree.BitString(H2B(AllZeros))}
	n.createBranch("0")
	if n.left == nil {
		t.Errorf("nil branch after create")
	}
}

// Test Copy on Write
func TestCreateBranchCOW(t *testing.T) {
	la := &node{epoch: 0, bindex: "0", depth: 1}
	lb := &node{epoch: 0, bindex: "1", depth: 1}
	r0 := &node{epoch: 0, bindex: "", left: la, right: lb}
	r1 := &node{epoch: 1, bindex: "", left: la, right: lb}

	var e0 int64
	var e1 int64 = 1

	r1.createBranch("0")
	if got, want := r1.left.epoch, e1; got != want {
		t.Errorf("r1.left.epoch = %v, want %v", got, want)
	}
	if got, want := r0.left.epoch, e0; got != want {
		t.Errorf("r0.left.epoch = %v, want %v", got, want)
	}
}

func H2B(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
