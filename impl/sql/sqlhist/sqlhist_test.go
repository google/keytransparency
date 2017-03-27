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

	"github.com/google/keytransparency/impl/sql/testutil"

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
	factory := testutil.NewFakeFactory(db)

	tree, err := New(ctx, db, 0, factory)
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}

	for _, tc := range []struct {
		index string
		leaf  []byte
		want  bool
	}{
		{strings.Repeat("A", 32), []byte("leaf"), true},
		{strings.Repeat("A", 32), []byte("leaf2"), true},
		{strings.Repeat("A", 32), []byte("leaf3"), true},
		{strings.Repeat("B", 32), []byte("leaf"), true},
		{strings.Repeat("C", 30), []byte("leaf"), false}, // errIndexLen
		{strings.Repeat("C", 30), nil, false},            // errNilLeaf

	} {
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		_, err = tree.QueueLeaf(txn, []byte(tc.index), tc.leaf)
		if got := err == nil; got != tc.want {
			t.Errorf("QueueLeaf(%v, %v): %v, want %v", tc.index, tc.leaf, got, tc.want)
			continue
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}
	}
}

func TestEpochNumAdvance(t *testing.T) {
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	factory := testutil.NewFakeFactory(db)

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
		tree, err := New(ctx, db, 0, factory)
		if err != nil {
			t.Fatalf("Failed to create SQL history: %v", err)
		}
		if tc.insert {
			txn, err := factory.NewDBTxn(ctx)
			if err != nil {
				t.Errorf("factory.NewDBTxn() failed: %v", err)
				continue
			}
			if _, err := tree.QueueLeaf(txn, []byte(tc.index), []byte(tc.leaf)); err != nil {
				t.Errorf("QueueLeaf(%v, %v): %v", tc.index, tc.leaf, err)
				continue
			}
			if err := txn.Commit(); err != nil {
				t.Errorf("txn.Commit() failed: %v", err)
			}
		}
		if got, err := tree.Commit(ctx); err != nil || got != tc.epoch {
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
	factory := testutil.NewFakeFactory(db)

	m, err := New(ctx, db, 0, factory)
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
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		if _, err := m.QueueLeaf(txn, index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", index, data, err)
			continue
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
			continue
		}

		epoch, err := m.Commit(ctx)
		if err != nil {
			t.Errorf("Commit()=[_, %v], want [_, nil]", err)
		}
		txn, err = factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		readData, err := m.ReadLeafAt(txn, index, epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, index, err)
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
			continue
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
	factory := testutil.NewFakeFactory(db)

	m, err := New(ctx, db, 0, factory)
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
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		var epoch int64 = 10
		readData, err := m.ReadLeafAt(txn, tc.index, epoch)
		if err != nil {
			t.Errorf("ReadLeafAt(%v, %v)=%v)", epoch, tc.index, err)
			continue
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
			continue
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
	factory := testutil.NewFakeFactory(db)

	m, err := New(ctx, db, 0, factory)
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
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		if _, err := m.QueueLeaf(txn, tc.index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v", tc.index, data, err)
			continue
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
			continue
		}

		if got, err := m.Commit(ctx); err != nil || got != tc.epoch {
			t.Errorf("Commit()=%v, %v, want %v, nil", got, err, tc.epoch)
		}

		for _, l := range leafs {
			txn, err := factory.NewDBTxn(ctx)
			if err != nil {
				t.Errorf("factory.NewDBTxn() failed: %v", err)
				continue
			}
			// Want success for leaves in previous epochs.
			want := l.epoch <= tc.epoch
			val, _ := m.ReadLeafAt(txn, l.index, tc.epoch)
			if got := val != nil; got != want {
				t.Errorf("ReadLeafAt(%v, %v)=%v, want %v)", l.index, tc.epoch, got, want)
				continue
			}
			if err := txn.Commit(); err != nil {
				t.Errorf("txn.Commit() failed: %v", err)
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
	factory := testutil.NewFakeFactory(db)

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
		m, err := New(ctx, db, 0, factory)
		if err != nil {
			t.Fatalf("Failed to create SQL history: %v", err)
		}
		// Iterating over a map in Go is randomized.
		for _, leaf := range leafs {
			txn, err := factory.NewDBTxn(ctx)
			if err != nil {
				t.Errorf("factory.NewDBTxn() failed: %v", err)
				continue
			}
			if _, err := m.QueueLeaf(txn, leaf.index, []byte(leaf.data)); err != nil {
				t.Errorf("WriteLeaf(%v, %v)=%v", leaf.index, leaf.data, err)
				continue
			}
			if err := txn.Commit(); err != nil {
				t.Errorf("txn.Commit() failed: %v", err)
				continue
			}

			if _, err := m.Commit(ctx); err != nil {
				t.Errorf("Commit()= %v, want nil", err)
			}
		}
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		r, err := m.ReadRootAt(txn, 10)
		if err != nil {
			t.Errorf("ReadRootAt() = %v", err)
			continue
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
			continue
		}
		roots[i] = r
	}
	// Verify that all the roots are the same.
	for i, r := range roots {
		if got, want := r, roots[0]; !bytes.Equal(got, want) {
			t.Errorf("root[%v] != root[0]: \ngot  %v\nwant %v", i, got, want)
		}
	}
}

type leaf struct {
	index []byte
	value string
}

func TestNeighborDepth(t *testing.T) {
	// Create testing environment.
	db, err := newDB()
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	// Construct a tree of the following form:
	//     r
	//       a
	//      3  4
	m1, err := createTree(db, 1, []leaf{
		{dh(defaultIndex[0]), "3"},
		{dh(defaultIndex[1]), "4"},
	})
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}
	// Construct a tree with only one item in it.
	m2, err := createTree(db, 2, []leaf{
		{dh(defaultIndex[0]), "0"},
	})
	if err != nil {
		t.Fatalf("Failed to create tree: %v", err)
	}

	// Run test cases.
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

func createTree(db *sql.DB, mapID int64, leafs []leaf) (*Map, error) {
	factory := testutil.NewFakeFactory(db)
	m, err := New(ctx, db, mapID, factory)
	if err != nil {
		return nil, fmt.Errorf("Failed to create map: %v", err)
	}
	for _, l := range leafs {
		txn, err := factory.NewDBTxn(ctx)
		if err != nil {
			return nil, fmt.Errorf("factory.NewDBTxn() failed: %v", err)
		}
		value := []byte(l.value)
		if _, err := m.QueueLeaf(txn, l.index, value); err != nil {
			return nil, fmt.Errorf("QueueLeaf(%v)=%v", l.index, err)
		}
		if err := txn.Commit(); err != nil {
			return nil, fmt.Errorf("txn.Commit() failed: %v", err)
		}
	}
	if epoch, err := m.Commit(ctx); err != nil || epoch != 0 {
		return nil, fmt.Errorf("Commit()=%v, %v, want %v, <nil>", epoch, err, 0)
	}
	return m, nil
}

// Hex to Bytes
func dh(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
