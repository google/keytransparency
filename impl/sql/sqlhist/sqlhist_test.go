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

package sqlhist

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/context"
)

var (
	ctx          = context.Background()
	AllZeros     = strings.Repeat("0", 256/4)
	defaultIndex = []string{
		"8000000000000000000000000000000000000000000000000000000000000001",
		"C000000000000000000000000000000000000000000000000000000000000001",
	}
)

func newDB() (*sql.DB, error) {
	return sql.Open("sqlite3", ":memory:")
}

func TestNewDB(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
}

func TestQueueLeaf(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()

	tree, err := New(db, "test")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}

	for _, tc := range []struct {
		index string
		leaf  string
		want  bool
	}{
		{strings.Repeat("A", 32), "leaf", true},
		{strings.Repeat("A", 32), "leaf2", false},
		{strings.Repeat("A", 32), "leaf3", false},
		{strings.Repeat("B", 32), "leaf", true},
	} {
		err := tree.QueueLeaf(nil, []byte(tc.index), []byte(tc.leaf))
		if got := err == nil; got != tc.want {
			t.Errorf("QueueLeaf(%v, %v): %v, want %v", tc.index, tc.leaf, got, tc.want)
		}
	}
}

func TestEpochNumAdvance(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()

	for _, tc := range []struct {
		index  string
		leaf   string
		epoch  int64
		insert bool
	}{
		{"", "", 0, false}, // Test commit without queue.
		{strings.Repeat("A", 32), "leafa", 1, true},
		{strings.Repeat("B", 32), "leafb", 2, true},
		{strings.Repeat("C", 32), "leafc", 3, true},
		{"", "", 4, false},
		{"", "", 5, false},
	} {
		tree, err := New(db, "test")
		if err != nil {
			t.Fatalf("Failed to create SQL history: %v", err)
		}
		if tc.insert {
			if err := tree.QueueLeaf(nil, []byte(tc.index), []byte(tc.leaf)); err != nil {
				t.Errorf("QueueLeaf(%v, %v): %v", tc.index, tc.leaf, err)
			}
		}
		if got, err := tree.Commit(); err != nil || got != tc.epoch {
			t.Errorf("Commit(): %v, %v, want %v", got, err, tc.epoch)
		}
		if got, _ := tree.readEpoch(); got != tc.epoch {
			t.Errorf("readEpoch(): %v, want %v", got, tc.epoch)
		}
	}
}

// TestQueueCommitRead ensures that saved data is returned.
func TestQueueCommitRead(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	m, err := New(db, "test")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	for i, index := range [][]byte{
		dh("0000000000000000000000000000000000000000000000000000000000000000"),
		dh("F000000000000000000000000000000000000000000000000000000000000000"),
		dh("2000000000000000000000000000000000000000000000000000000000000000"),
		dh("C000000000000000000000000000000000000000000000000000000000000000"),
	} {
		data := []byte{byte(i)}
		if err := m.QueueLeaf(ctx, index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", index, data, err)
		}
		epoch, err := m.Commit()
		if err != nil {
			t.Errorf("Commit()=[_, %v], want [_, nil]", err)
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

func TestReadNotFound(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	m, err := New(db, "test")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	for _, tc := range []struct {
		index []byte
	}{
		{dh("0000000000000000000000000000000000000000000000000000000000000000")},
		{dh("F000000000000000000000000000000000000000000000000000000000000000")},
		{dh("2000000000000000000000000000000000000000000000000000000000000000")},
		{dh("C000000000000000000000000000000000000000000000000000000000000000")},
	} {
		var epoch int64 = 10
		readData, err := m.ReadLeafAt(ctx, tc.index, epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, tc.index, err)
		}
		if got := readData; got != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v, want %v", epoch, tc.index, got, nil)
		}
	}
}

// Verify that leaves written in previous epochs can still be read.
func TestReadPreviousEpochs(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	m, err := New(db, "test")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	leafs := []struct {
		index []byte
		epoch int64
	}{
		{dh("0000000000000000000000000000000000000000000000000000000000000000"), 0},
		{dh("F000000000000000000000000000000000000000000000000000000000000000"), 1},
		{dh("2000000000000000000000000000000000000000000000000000000000000000"), 2},
		{dh("C000000000000000000000000000000000000000000000000000000000000000"), 3},
	}
	for i, tc := range leafs {
		data := []byte{byte(i)}
		if err := m.QueueLeaf(ctx, tc.index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", tc.index, data, err)
		}
		if got, err := m.Commit(); err != nil || got != tc.epoch {
			t.Errorf("Commit()=%v, %v, want %v, nil", got, err, tc.epoch)
		}

		for _, l := range leafs {
			// Want success for leaves in previous epochs.
			want := l.epoch <= tc.epoch
			val, _ := m.ReadLeafAt(ctx, l.index, tc.epoch)
			if got := val != nil; got != want {
				t.Errorf("ReadLeafAt(%v, %v)=%v, want %v)", l.index, tc.epoch, got, want)
			}
		}
	}
}

// Verify that arbitrary insertion and commit order produces same tree root.
func TestAribtrayInsertOrder(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	leafs := []struct {
		index []byte
		data  string
	}{
		{dh("0000000000000000000000000000000000000000000000000000000000000000"), "0"},
		{dh("F000000000000000000000000000000000000000000000000000000000000000"), "1"},
		{dh("2000000000000000000000000000000000000000000000000000000000000000"), "2"},
		{dh("C000000000000000000000000000000000000000000000000000000000000000"), "3"},
		{dh("D000000000000000000000000000000000000000000000000000000000000000"), "4"},
		{dh("E000000000000000000000000000000000000000000000000000000000000000"), "5"},
	}
	roots := make([][]byte, len(leafs))
	for i := range roots {
		m, err := New(db, fmt.Sprintf("test%v", i))
		if err != nil {
			t.Fatalf("Failed to create SQL history: %v", err)
		}
		// Iterating over a map in Go is randomized.
		for _, leaf := range leafs {
			if err := m.QueueLeaf(ctx, leaf.index, []byte(leaf.data)); err != nil {
				t.Errorf("WriteLeaf(%v, %v)=%v", leaf.index, leaf.data, err)
			}
			if _, err := m.Commit(); err != nil {
				t.Errorf("Commit()= %v, want nil", err)
			}
		}
		r, err := m.ReadRootAt(nil, 10)
		roots[i] = r
		if err != nil {
			t.Errorf("ReadRootAt() = %v", err)
		}
	}
	// Verify that all the roots are the same.
	for i, r := range roots {
		if got, want := r, roots[0]; !bytes.Equal(got, want) {
			t.Errorf("root[%v] != root[0]: \ngot  %v\nwant %v", i, got, want)
		}
	}
}

func TestNeighborDepth(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	m1, err := New(db, "test1")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	// Construct a tree of the following form:
	//     r
	//       a
	//      3  4
	for _, l := range []struct {
		index []byte
		value string
	}{
		{dh(defaultIndex[0]), "3"},
		{dh(defaultIndex[1]), "4"},
	} {
		value := []byte(l.value)
		if err := m1.QueueLeaf(ctx, l.index, value); err != nil {
			t.Fatalf("QueueLeaf(%v)=%v", l.index, err)
		}
	}
	if epoch, err := m1.Commit(); err != nil || epoch != 0 {
		t.Fatalf("Commit()=%v, %v, want %v, <nil>", epoch, err, 0)
	}

	// Construct a tree with only one item in it.
	m2, err := New(db, "test2")
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	dindex, err := hex.DecodeString(defaultIndex[0])
	if err != nil {
		t.Fatalf("DecodeString(%v)=(_, %v)", defaultIndex[0], err)
	}
	if err := m2.QueueLeaf(nil, dindex, []byte("0")); err != nil {
		t.Fatalf("QueueLeaf failed: %v", err)
	}
	if _, err := m2.Commit(); err != nil {
		t.Fatalf("Commit failed: %v", err)
	}
	for _, tc := range []struct {
		m     *Map
		index []byte
		depth int
	}{
		{m1, dh(AllZeros), 1},        // Proof of absence.
		{m1, dh(defaultIndex[0]), 2}, // Proof of presence.
		{m1, dh(defaultIndex[1]), 2},
		{m2, dh(defaultIndex[0]), 0},
	} {
		nbrs, _ := tc.m.NeighborsAt(ctx, tc.index, 0)
		if got, want := len(nbrs), maxDepth; got != want {
			t.Errorf("len(nbrs): %v, want %v", got, want)
		}
		if got := PrefixLen(nbrs); got != tc.depth {
			t.Errorf("PrefixLen(NeighborsAt(%v))=%v, want %v", tc.index, got, tc.depth)

		}
	}
}

// Hex to Bytes
func dh(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
