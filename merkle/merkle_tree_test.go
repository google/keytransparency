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

package merkle

import (
	"encoding/hex"
	"bytes"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
)

const (
	testCommitmentTimestamp = 1
)

var AllZeros = strings.Repeat("0", 256)

type Fatal func(format string, args ...interface{})

func hexToBytes(fatal Fatal, s string) []byte {
	result, err := hex.DecodeString(s)
	if err != nil {
		fatal("Hex decoding '%v' failed: %v", s, err)
	}
	return result
}

func TestBitString(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{"00", AllZeros},
	}

	for i, test := range tests {
		if got, want := BitString(hexToBytes(t.Fatalf, test.input)), test.output; got != want {
			t.Errorf("Test[%v]: BitString(%v)=%v, want %v", i, test.input, got, want)
		}
	}
}

func TestAddRoot(t *testing.T) {
	m := New()
	tests := []struct {
		epoch uint64
		code  codes.Code
	}{
		{10, codes.OK},
		{10, codes.OK},
		{11, codes.OK},
		{10, codes.FailedPrecondition},
		{12, codes.OK},
	}
	for i, test := range tests {
		_, err := m.addRoot(test.epoch)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: addRoot(%v)=%v, want %v", i, test.epoch, got, want)
		}
	}
}

func TestAddLeaf(t *testing.T) {
	m := New()
	tests := []struct {
		epoch uint64
		index string
		code  codes.Code
	}{
		// First insert
		{0, "0000000000000000000000000000000000000000000000000000000000000000", codes.OK},
		// Inserting a duplicate in the same epoch should fail.
		{0, "0000000000000000000000000000000000000000000000000000000000000000", codes.AlreadyExists},
		// Insert a leaf node with a long shared prefix. Should increase tree depth to max.
		{0, "0000000000000000000000000000000000000000000000000000000000000001", codes.OK},
		// Insert a leaf node with a short shared prefix. Should be placed near the root.
		{0, "8000000000000000000000000000000000000000000000000000000000000001", codes.OK},
		// Update a leaf node in the next epoch. Should be placed at the same level as the previous epoch.
		{1, "8000000000000000000000000000000000000000000000000000000000000001", codes.OK},
		{1, "0000000000000000000000000000000000000000000000000000000000000001", codes.OK},
		{5, "8000000000000000000000000000000000000000000000000000000000000001", codes.OK},
	}
	for i, test := range tests {
		err := m.AddLeaf([]byte{}, test.epoch, hexToBytes(t.Fatalf, test.index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v, %v",
				i, test.epoch, test.index, got, want, err)
		}
	}
}

var letters = []rune("01234567890abcdef")

func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func BenchmarkAddLeaf(b *testing.B) {
	m := New()
	var epoch uint64
	for i := 0; i < b.N; i++ {
		index := randSeq(64)
		err := m.AddLeaf([]byte{}, epoch, hexToBytes(b.Fatalf, index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, index, got, want)
		}
	}
}

func BenchmarkAddLeafAdvanceEpoch(b *testing.B) {
	m := New()
	var epoch uint64
	for i := 0; i < b.N; i++ {
		index := randSeq(64)
		epoch++
		err := m.AddLeaf([]byte{}, epoch, hexToBytes(b.Fatalf, index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, index, got, want)
		}
	}
}

func BenchmarkAudit(b *testing.B) {
	m := New()
	var epoch uint64
	items := make([]string, 0, b.N)
	for i := 0; i < b.N; i++ {
		index := randSeq(64)
		items = append(items, index)
		err := m.AddLeaf([]byte{}, epoch, hexToBytes(b.Fatalf, index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, index, got, want)
		}
	}
	for _, v := range items {
		m.AuditPath(epoch, hexToBytes(b.Fatalf, v))
	}
}

func TestPushDown(t *testing.T) {
	n := &node{index: BitString(hexToBytes(t.Fatalf, AllZeros))}
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
	n := &node{index: BitString(hexToBytes(t.Fatalf, AllZeros))}
	n.createBranch("0")
	if n.left == nil {
		t.Errorf("nil branch after create")
	}
}

func TestCreateBranchCOW(t *testing.T) {
	la := &node{epoch: 0, index: "0", depth: 1}
	lb := &node{epoch: 0, index: "1", depth: 1}
	r0 := &node{epoch: 0, index: "", left: la, right: lb}
	r1 := &node{epoch: 1, index: "", left: la, right: lb}

	var e0 uint64
	var e1 uint64 = 1

	r1.createBranch("0")
	if got, want := r1.left.epoch, e1; got != want {
		t.Errorf("r1.left.epoch = %v, want %v", got, want)
	}
	if got, want := r0.left.epoch, e0; got != want {
		t.Errorf("r0.left.epoch = %v, want %v", got, want)
	}
}

func TestAuditDepth(t *testing.T) {
	m := New()
	tests := []struct {
		epoch uint64
		index string
		depth int
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000", 256},
		{0, "0000000000000000000000000000000000000000000000000000000000000001", 256},
		{0, "8000000000000000000000000000000000000000000000000000000000000001", 1},
		{1, "8000000000000000000000000000000000000000000000000000000000000001", 1},
		{1, "0000000000000000000000000000000000000000000000000000000000000001", 256},
	}
	for i, test := range tests {
		err := m.AddLeaf([]byte{}, test.epoch, hexToBytes(t.Fatalf, test.index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v",
				i, test.epoch, test.index, got, want)
		}
	}

	for i, test := range tests {
		audit, err := m.AuditPath(test.epoch, hexToBytes(t.Fatalf, test.index))
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AuditPath(_, %v, %v)=%v, want %v",
				i, test.epoch, test.index, got, want)
		}
		if got, want := len(audit), test.depth; got != want {
			for j, a := range audit {
				fmt.Println(j, ": ", a)
			}
			t.Errorf("Test[%v]: len(audit(%v, %v))=%v, want %v", i, test.epoch, test.index, got, want)
		}
	}
}

func TestAuditNeighors(t *testing.T) {
	m := New()
	tests := []struct {
		epoch         uint64
		index         string
		emptyNeighors []bool
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000", []bool{}},
		{0, "F000000000000000000000000000000000000000000000000000000000000000", []bool{false}},
		{0, "2000000000000000000000000000000000000000000000000000000000000000", []bool{false, true, false}},
		{0, "C000000000000000000000000000000000000000000000000000000000000000", []bool{false, true, false}},
	}
	for i, test := range tests {
		// Insert.
		err := m.AddLeaf([]byte{}, test.epoch, hexToBytes(t.Fatalf, test.index), testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v",
				i, test.epoch, test.index, got, want)
		}
		// Verify audit path.
		audit, err := m.AuditPath(test.epoch, hexToBytes(t.Fatalf, test.index))
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AuditPath(_, %v, %v)=%v, want %v",
				i, test.epoch, test.index, got, want)
		}
		if got, want := len(audit), len(test.emptyNeighors); got != want {
			for j, a := range audit {
				fmt.Println(j, ": ", a)
			}
			t.Errorf("Test[%v]: len(audit(%v, %v))=%v, want %v", i, test.epoch, test.index, got, want)
		}
		for j, v := range test.emptyNeighors {
			// Starting from the leaf, going to the root. Skipping leaf.
			depth := len(audit) - j
			nstr := neighborOf(BitString(hexToBytes(t.Fatalf, test.index)), depth)
			if got, want := bytes.Equal(audit[j], EmptyValue(nstr)), v; got != want {
				t.Errorf("Test[%v]: AuditPath(%v)[%v]=%v, want %v", i, test.index, j, got, want)
			}
		}
	}
}

func neighborOf(index string, depth int) string {
	return index[:depth-1] + string(neighbor(index[depth-1]))
}

func TestGetLeafCommitmentTimestamp(t *testing.T) {
	m := New()
	// Adding few leaves with commitment timestamps to the tree.
	addValidLeaves(t, m)

	// Get commitment timestamps.
	tests := []struct {
		epoch           uint64
		index           string
		outCommitmentTS uint64
		code            codes.Code
	}{
		// Get commitment timestamps of all added leaves. Ordering doesn't matter
		{1, "8000000000000000000000000000000000000000000000000000000000000001", 4, codes.OK},
		{0, "0000000000000000000000000000000000000000000000000000000000000000", 1, codes.OK},
		{1, "0000000000000000000000000000000000000000000000000000000000000001", 5, codes.OK},
		{0, "0000000000000000000000000000000000000000000000000000000000000001", 2, codes.OK},
		{0, "8000000000000000000000000000000000000000000000000000000000000001", 3, codes.OK},
		// Invalid index lengh.
		{1, "8000", 0, codes.InvalidArgument},
		// Not found due to missing epoch.
		{3, "8000000000000000000000000000000000000000000000000000000000000001", 0, codes.NotFound},
		// Not found due to reaching bottom of the tree.
		{1, "8000000000000000000000000000000000000000000000000000000000000002", 0, codes.NotFound},
		// Not found due to reaching bottom of the tree.
		{0, "0000000000000000000000000000000000000000000000000000000000000002", 0, codes.NotFound},
	}
	for i, test := range tests {
		commitmentTS, err := m.GetLeafCommitmentTimestamp(test.epoch, hexToBytes(t.Fatalf, test.index))
		if gotc, wantc, gote, wante := commitmentTS, test.outCommitmentTS, grpc.Code(err), test.code; gotc != wantc || gote != wante {
			t.Errorf("Test[%v]: GetLeafCommitmentTimestamp(%v, %v)=(%v, %v), want (%v, %v), err = %v",
				i, test.epoch, test.index, gotc, gote, wantc, wante, err)
		}
	}
}

func addValidLeaves(t *testing.T, m *Tree) {
	tests := []struct {
		epoch        uint64
		index        string
		commitmentTS uint64
		code         codes.Code
	}{
		// First insert
		{0, "0000000000000000000000000000000000000000000000000000000000000000", 1, codes.OK},
		// Insert a leaf node with a long shared prefix. Should increase
		// tree depth to max.
		{0, "0000000000000000000000000000000000000000000000000000000000000001", 2, codes.OK},
		// Insert a leaf node with a short shared prefix. Should be
		// placed near the root.
		{0, "8000000000000000000000000000000000000000000000000000000000000001", 3, codes.OK},
		// Update a leaf node in the next epoch. Should be placed at the
		// same level as the previous epoch.
		{1, "8000000000000000000000000000000000000000000000000000000000000001", 4, codes.OK},
		{1, "0000000000000000000000000000000000000000000000000000000000000001", 5, codes.OK},
	}
	for i, test := range tests {
		err := m.AddLeaf([]byte{}, test.epoch, hexToBytes(t.Fatalf, test.index), test.commitmentTS)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Fatalf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v, %v",
				i, test.epoch, test.index, got, want, err)
		}
	}
}
