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
	"bytes"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	cm "github.com/google/e2e-key-server/common/merkle"
)

const (
	testCommitmentTimestamp = 1
)

var (
	AllZeros = strings.Repeat("0", 256)
	// validTreeLeaves contains valid leaves that will be added to the test
	// valid tree. All these leaves will be added to the test tree using the
	// addValidLeaves function.
	validTreeLeaves = []Leaf{
		{0, "0000000000000000000000000000000000000000000000000000000000000000", 1},
		{0, "0000000000000000000000000000000000000000000000000000000000000001", 2},
		{0, "8000000000000000000000000000000000000000000000000000000000000001", 3},
		{1, "8000000000000000000000000000000000000000000000000000000000000001", 4},
		{1, "0000000000000000000000000000000000000000000000000000000000000001", 5},
	}
)

type Leaf struct {
	epoch        uint64
	hindex       string
	commitmentTS uint64
}

type Env struct {
	m *Tree
}

func NewEnv(t *testing.T) *Env {
	m := New()
	// Adding few leaves with commitment timestamps to the tree.
	addValidLeaves(t, m)

	return &Env{m}
}

func addValidLeaves(t *testing.T, m *Tree) {
	for i, leaf := range validTreeLeaves {
		index, err := hexToBytes(leaf.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", leaf.hindex, err)
		}
		err = m.AddLeaf([]byte{}, leaf.epoch, index, leaf.commitmentTS)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Fatalf("Leaf[%v]: AddLeaf(_, %v, %v)=%v, want %v, %v",
				i, leaf.epoch, leaf.hindex, got, want, err)
		}
	}
}

func hexToBytes(s string) ([]byte, error) {
	result, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func TestAddRoot(t *testing.T) {
	t.Parallel()

	m := New()
	tests := []struct {
		epoch uint64
		code  codes.Code
	}{
		{0, codes.OK},
		{1, codes.OK},
		{2, codes.OK},
		{3, codes.OK},
		{3, codes.OK},
		{1, codes.FailedPrecondition},
		{10, codes.FailedPrecondition},
	}
	for i, test := range tests {
		err := m.AddRoot(test.epoch)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: addRoot(%v)=%v, want %v", i, test.epoch, got, want)
		}
	}
}

func TestAddExistingLeaf(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	tests := []struct {
		leaf Leaf
		code codes.Code
	}{
		{validTreeLeaves[4], codes.OK},
	}
	for i, test := range tests {
		index, err := hexToBytes(test.leaf.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.leaf.hindex, err)
		}
		err = env.m.AddLeaf([]byte{}, test.leaf.epoch, index, test.leaf.commitmentTS)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v, %v",
				i, test.leaf.epoch, test.leaf.hindex, got, want, err)
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
		hindex := randSeq(64)
		index, err := hexToBytes(hindex)
		if err != nil {
			b.Fatalf("Hex decoding of '%v' failed: %v", hindex, err)
		}
		err = m.AddLeaf([]byte{}, epoch, index, testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, hindex, got, want)
		}
	}
}

func BenchmarkAddLeafAdvanceEpoch(b *testing.B) {
	m := New()
	var epoch uint64
	for i := 0; i < b.N; i++ {
		hindex := randSeq(64)
		index, err := hexToBytes(hindex)
		if err != nil {
			b.Fatalf("Hex decoding of '%v' failed: %v", hindex, err)
		}
		epoch++
		err = m.AddLeaf([]byte{}, epoch, index, testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, hindex, got, want)
		}
	}
}

func BenchmarkAudit(b *testing.B) {
	m := New()
	var epoch uint64
	items := make([]string, 0, b.N)
	for i := 0; i < b.N; i++ {
		hindex := randSeq(64)
		index, err := hexToBytes(hindex)
		if err != nil {
			b.Fatalf("Hex decoding of '%v' failed: %v", hindex, err)
		}
		items = append(items, hindex)
		err = m.AddLeaf([]byte{}, epoch, index, testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			b.Errorf("%v: AddLeaf(_, %v, %v)=%v, want %v",
				i, epoch, hindex, got, want)
		}
	}
	for _, v := range items {
		index, err := hexToBytes(v)
		if err != nil {
			b.Fatalf("Hex decoding of '%v' failed: %v", v, err)
		}
		m.AuditPath(epoch, index)
	}
}

func TestPushDown(t *testing.T) {
	t.Parallel()

	index, err := hexToBytes(AllZeros)
	if err != nil {
		t.Fatalf("Hex decoding of '%v' failed: %v", AllZeros, err)
	}
	n := &node{bindex: bitString(index)}
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
	t.Parallel()

	index, err := hexToBytes(AllZeros)
	if err != nil {
		t.Fatalf("Hex decoding of '%v' failed: %v", AllZeros, err)
	}
	n := &node{bindex: bitString(index)}
	n.createBranch("0")
	if n.left == nil {
		t.Errorf("nil branch after create")
	}
}

func TestCreateBranchCOW(t *testing.T) {
	t.Parallel()

	la := &node{epoch: 0, bindex: "0", depth: 1}
	lb := &node{epoch: 0, bindex: "1", depth: 1}
	r0 := &node{epoch: 0, bindex: "", left: la, right: lb}
	r1 := &node{epoch: 1, bindex: "", left: la, right: lb}

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
	t.Parallel()

	env := NewEnv(t)

	tests := []struct {
		leaf  Leaf
		depth int
	}{
		{validTreeLeaves[0], 256},
		{validTreeLeaves[1], 256},
		{validTreeLeaves[2], 1},
		{validTreeLeaves[3], 1},
		{validTreeLeaves[4], 256},
	}

	for i, test := range tests {
		index, err := hexToBytes(test.leaf.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.leaf.hindex, err)
		}
		audit, _, err := env.m.AuditPath(test.leaf.epoch, index)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AuditPath(_, %v, %v)=%v, want %v",
				i, test.leaf.epoch, test.leaf.hindex, got, want)
		}
		if got, want := len(audit), test.depth; got != want {
			for j, a := range audit {
				fmt.Println(j, ": ", a)
			}
			t.Errorf("Test[%v]: len(audit(%v, %v))=%v, want %v", i, test.leaf.epoch, test.leaf.hindex, got, want)
		}
	}
}

func TestAuditNeighors(t *testing.T) {
	t.Parallel()

	m := New()
	tests := []struct {
		epoch         uint64
		hindex        string
		emptyNeighors []bool
	}{
		{0, "0000000000000000000000000000000000000000000000000000000000000000", []bool{}},
		{0, "F000000000000000000000000000000000000000000000000000000000000000", []bool{false}},
		{0, "2000000000000000000000000000000000000000000000000000000000000000", []bool{false, true, false}},
		{0, "C000000000000000000000000000000000000000000000000000000000000000", []bool{false, true, false}},
	}
	for i, test := range tests {
		index, err := hexToBytes(test.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.hindex, err)
		}
		// Insert.
		err = m.AddLeaf([]byte{}, test.epoch, index, testCommitmentTimestamp)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AddLeaf(_, %v, %v)=%v, want %v",
				i, test.epoch, test.hindex, got, want)
		}
		// Verify audit path.
		audit, _, err := m.AuditPath(test.epoch, index)
		if got, want := grpc.Code(err), codes.OK; got != want {
			t.Errorf("Test[%v]: AuditPath(_, %v, %v)=%v, want %v",
				i, test.epoch, test.hindex, got, want)
		}
		if got, want := len(audit), len(test.emptyNeighors); got != want {
			for j, a := range audit {
				fmt.Println(j, ": ", a)
			}
			t.Errorf("Test[%v]: len(audit(%v, %v))=%v, want %v", i, test.epoch, test.hindex, got, want)
		}
		for j, v := range test.emptyNeighors {
			// Starting from the leaf's neighbor, going to the root.
			depth := len(audit) - j
			nstr := neighborOf(bitString(index), depth)
			value := cm.EmptyLeafValue(nstr)
			if got, want := bytes.Equal(audit[j], value), v; got != want {
				t.Errorf("Test[%v]: AuditPath(%v)[%v]=%v, want %v", i, test.hindex, j, got, want)
			}
		}
	}
}

func neighborOf(hindex string, depth int) string {
	return hindex[:depth-1] + string(neighbor(hindex[depth-1]))
}

func TestLongestPrefixMatch(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)

	// Get commitment timestamps.
	tests := []struct {
		leaf            Leaf
		outCommitmentTS uint64
		code            codes.Code
	}{
		// Get commitment timestamps of all added leaves. Ordering doesn't matter
		{validTreeLeaves[3], validTreeLeaves[3].commitmentTS, codes.OK},
		{validTreeLeaves[0], validTreeLeaves[0].commitmentTS, codes.OK},
		{validTreeLeaves[4], validTreeLeaves[4].commitmentTS, codes.OK},
		{validTreeLeaves[1], validTreeLeaves[1].commitmentTS, codes.OK},
		{validTreeLeaves[2], validTreeLeaves[2].commitmentTS, codes.OK},
		// Add custom testing leaves.
		// Invalid index lengh.
		{Leaf{1, "8000", 0}, 0, codes.InvalidArgument},
		// Not found due to missing epoch.
		{Leaf{3, "8000000000000000000000000000000000000000000000000000000000000001", 0}, 0, codes.InvalidArgument},
		// Found another leaf.
		{Leaf{1, "8000000000000000000000000000000000000000000000000000000000000002", 0}, 4, codes.OK},
		// Found empty branch.
		{Leaf{0, "0000000000000000000000000000000000000000000000000000000000000002", 0}, 0, codes.OK},
	}
	for i, test := range tests {
		index, err := hexToBytes(test.leaf.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.leaf.hindex, err)
		}
		_, commitmentTS, err := env.m.AuditPath(test.leaf.epoch, index)
		if gotc, wantc, gote, wante := commitmentTS, test.outCommitmentTS, grpc.Code(err), test.code; gotc != wantc || gote != wante {
			t.Errorf("Test[%v]: LongestPrefixMatch(%v, %v)=(%v, %v), want (%v, %v), err = %v",
				i, test.leaf.epoch, test.leaf.hindex, gotc, gote, wantc, wante, err)
		}
	}
}

func TestRoot(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)

	tests := []struct {
		epoch uint64
		code  codes.Code
	}{
		{0, codes.OK},
		{1, codes.OK},
		{5, codes.NotFound},
	}

	for i, test := range tests {
		_, err := env.m.Root(test.epoch)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: Root(%v)=%v, want %v", i, test.epoch, got, want)
		}
	}
}

func TestFromNeighbors(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)

	tests := []struct {
		leaf Leaf
	}{
		{validTreeLeaves[0]},
		{validTreeLeaves[1]},
		{validTreeLeaves[2]},
		{validTreeLeaves[3]},
		{validTreeLeaves[4]},
	}

	// Get current epoch of the test tree.
	epoch := validTreeLeaves[4].epoch
	// Get expected root value.
	expectedRoot, err := env.m.Root(epoch)
	if err != nil {
		t.Fatalf("Error while getting tree root value in epoch %v: %v", epoch, err)
	}

	for i, test := range tests {
		index, err := hexToBytes(test.leaf.hindex)
		if err != nil {
			t.Fatalf("Hex decoding of '%v' failed: %v", test.leaf.hindex, err)
		}
		neighbors, _, err := env.m.AuditPath(test.leaf.epoch, index)

		tmp, err := FromNeighbors(neighbors, index, []byte{})
		if err != nil {
			t.Fatalf("Error while building the expected tree: %v", err)
		}

		calculatedRoot, err := tmp.Root(0)
		if err != nil {
			t.Fatalf("Test[%v]: Error while getting tree root value in epoch %v: %v", i, epoch, err)
		}

		if got, want := hmac.Equal(expectedRoot, calculatedRoot), true; got != want {
			t.Error("Test[%v]: FromNeighbors(_, %v, _)=%v, wamt %v", i, test.leaf.hindex, got, want)
		}
	}
}
