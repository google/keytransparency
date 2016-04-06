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
	"log"
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

func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func TestNew(t *testing.T) {
	db := newDB(t)
	defer db.Close()
}

func TestQueueLeaf(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	tree := New(db, "test")

	tests := []struct {
		index string
		leaf  string
		want  bool
	}{
		{strings.Repeat("A", 32), "leaf", true},
		{strings.Repeat("A", 32), "leaf2", false},
		{strings.Repeat("A", 32), "leaf3", false},
		{strings.Repeat("B", 32), "leaf", true},
	}
	for _, tc := range tests {
		err := tree.QueueLeaf(nil, []byte(tc.index), []byte(tc.leaf))
		if got := err == nil; got != tc.want {
			t.Errorf("QueueLeaf(%v, %v): %v, want %v", tc.index, tc.leaf, got, tc.want)
		}
	}
}

func TestEpochNumAdvance(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	tests := []struct {
		index string
		leaf  string
		epoch int64
		want  bool
	}{
		{strings.Repeat("A", 32), "leafa", 0, true},
		{strings.Repeat("B", 32), "leafb", 1, true},
		{strings.Repeat("C", 32), "leafc", 2, true},
	}
	for _, tc := range tests {
		tree := New(db, "test")
		// Verify that the epoch does not exist before Commit()
		_, err := tree.ReadRootAt(nil, tc.epoch)
		if got := err == nil; got != tc.want {
			t.Errorf("before: ReadRootAt(%v) succeeded, want %v", tc.epoch, tc.want)
		}
		err = tree.QueueLeaf(nil, []byte(tc.index), []byte(tc.leaf))
		if got := err == nil; got != true {
			t.Errorf("QueueLeaf(%v, %v): %v", tc.index, tc.leaf, err)
		}
		e, err := tree.Commit()
		if got := err == nil; got != true {
			t.Errorf("Commit(): %v", err)
		}
		if got := e; got != tc.epoch {
			t.Errorf("Commit(): %v, want %v", got, tc.epoch)
		}
		// Verify that it does exist after Commit()
		_, err = tree.ReadRootAt(nil, tc.epoch)
		if got := err == nil; got != true {
			t.Errorf("after: ReadRootAt(%v): %v, want nil", tc.epoch, err)
		}
	}
}

// TestQueueCommitRead ensures that saved data is returned.
func TestQueueCommitRead(t *testing.T) {
	db := newDB(t)
	defer db.Close()
	m := New(db, "test")
	leafs := []struct {
		hindex string
	}{
		{"0000000000000000000000000000000000000000000000000000000000000000"},
		{"F000000000000000000000000000000000000000000000000000000000000000"},
		{"2000000000000000000000000000000000000000000000000000000000000000"},
		{"C000000000000000000000000000000000000000000000000000000000000000"},
	}
	for i, tc := range leafs {
		data := []byte{byte(i)}
		if err := m.QueueLeaf(ctx, H2B(tc.hindex), data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", tc.hindex, data, err)
		}
		epoch, err := m.Commit()
		if err != nil {
			t.Errorf("Commit()=%v, %v, want %v, nil", epoch, err)
		}
		readData, err := m.ReadLeafAt(ctx, H2B(tc.hindex), epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, tc.hindex, err)
		}
		if got, want := readData, data; !bytes.Equal(got, want) {
			t.Errorf("ReadLeafAt(%v, %v)=%v, want %v", epoch, tc.hindex, got, want)
		}
	}
}

func TestReadNotFound(t *testing.T) {
	db := newDB(t)
	defer db.Close()
	m := New(db, "test")
	leafs := []struct {
		hindex string
	}{
		{"0000000000000000000000000000000000000000000000000000000000000000"},
		{"F000000000000000000000000000000000000000000000000000000000000000"},
		{"2000000000000000000000000000000000000000000000000000000000000000"},
		{"C000000000000000000000000000000000000000000000000000000000000000"},
	}
	for _, tc := range leafs {
		var epoch int64 = 10
		readData, err := m.ReadLeafAt(ctx, H2B(tc.hindex), epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, tc.hindex, err)
		}
		if got := readData; got != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v, want %v", epoch, tc.hindex, got, nil)
		}
	}
}

// Verify that leaves written in previous epochs can still be read.
func TestReadPreviousEpochs(t *testing.T) {
	db := newDB(t)
	defer db.Close()
	m := New(db, "test")
	leafs := []struct {
		hindex string
		epoch  int64
	}{
		{"0000000000000000000000000000000000000000000000000000000000000000", 0},
		{"F000000000000000000000000000000000000000000000000000000000000000", 1},
		{"2000000000000000000000000000000000000000000000000000000000000000", 2},
		{"C000000000000000000000000000000000000000000000000000000000000000", 3},
	}
	for i, tc := range leafs {
		data := []byte{byte(i)}
		if err := m.QueueLeaf(ctx, H2B(tc.hindex), data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", tc.hindex, data, err)
		}
		if got, err := m.Commit(); err != nil || got != tc.epoch {
			t.Errorf("Commit()=%v, %v, want %v, nil", got, err, tc.epoch)
		}

		for _, l := range leafs {
			// Want success for leaves in previous epochs.
			want := l.epoch <= tc.epoch
			val, _ := m.ReadLeafAt(ctx, H2B(l.hindex), tc.epoch)
			if got := val != nil; got != want {
				t.Errorf("ReadLeafAt(%v, %v)=%v, want %v)", l.hindex, tc.epoch, got, want)
			}
		}
	}
}

func TestNeighborDepth(t *testing.T) {
	db := newDB(t)
	defer db.Close()
	m1 := New(db, "test1")
	// Construct a tree of the following form:
	//     r
	//       a
	//      3  4
	leafs := []struct {
		hindex string
		value  string
	}{
		{defaultIndex[0], "3"},
		{defaultIndex[1], "4"},
	}
	for _, l := range leafs {
		value := []byte(l.value)
		if err := m1.QueueLeaf(ctx, H2B(l.hindex), value); err != nil {
			t.Fatalf("QueueLeaf(%v)=%v", l.hindex, err)
		}
	}
	if epoch, err := m1.Commit(); err != nil || epoch != 0 {
		t.Fatalf("Commit()=%v, %v, want %v, <nil>", epoch, err, 0)
	}

	// Construct a tree with only one item in it.
	m2 := New(db, "test2")
	m2.QueueLeaf(nil, H2B(defaultIndex[0]), []byte("0"))
	m2.Commit()
	tests := []struct {
		m      *Map
		hindex string
		depth  int
	}{
		{m1, AllZeros, 1},        // Proof of absence.
		{m1, defaultIndex[0], 2}, // Proof of presence.
		{m1, defaultIndex[1], 2},
		{m2, defaultIndex[0], 0},
	}
	for _, tc := range tests {
		nbrs, _ := tc.m.NeighborsAt(ctx, H2B(tc.hindex), 0)
		if got := PrefixLen(nbrs); got != tc.depth {
			t.Errorf("PrefixLen(NeighborsAt(%v))=%v, want %v", tc.hindex, got, tc.depth)
			log.Printf("nbrs: %v", nbrs)

		}
	}
}

// PrefixLen returns the index of the last non-zero item in the list
func PrefixLen(nodes [][]byte) int {
	// Iterate over the nodes from leaf to root.
	for i, v := range nodes {
		if v != nil {
			// return the first non-empty node.
			return len(nodes) - i
		}
	}
	return 0
}

// Hex to Bytes
func H2B(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
