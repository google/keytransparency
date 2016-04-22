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

package memtree

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/e2e-key-server/tree/sparse/sqlhist"
	"golang.org/x/net/context"
)

var (
	ctx          = context.Background()
	AllZeros     = strings.Repeat("0", 256/4)
	defaultIndex = []string{
		"8000000000000000000000000000000000000000000000000000000000000001",
		"C000000000000000000000000000000000000000000000000000000000000001",
		"4000000000000000000000000000000000000000000000000000000000000001",
	}
)

func TestWriteRead(t *testing.T) {
	m := New()
	leafs := []struct {
		hindex string
		value  string
	}{
		{defaultIndex[0], "3"},
		{defaultIndex[1], "4"},
	}
	for _, test := range leafs {
		index := H2B(test.hindex)
		data := []byte(test.value)
		if err := m.WriteLeaf(ctx, index, data); err != nil {
			t.Errorf("WriteLeaf(%v, %v)=%v)", test.hindex, data, err)
		}
		readData, err := m.ReadLeaf(ctx, index)
		if err != nil {
			t.Errorf("ReadLeaf(%v)=%v)", index, err)
		}
		if got, want := readData, data; !bytes.Equal(got, want) {
			t.Errorf("ReadLeaf(%v)=%v, want %v", index, got, want)
		}
	}
}

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
		if err := m.WriteLeaf(ctx, H2B(l.hindex), value); err != nil {
			t.Fatalf("QueueLeaf(%v)=%v", l.hindex, err)
		}
	}
	return m
}

func TestNeighborDepth(t *testing.T) {
	m := DefaultTree(t)
	tests := []struct {
		hindex string
		depth  int
	}{
		{AllZeros, 1},        // Proof of absence.
		{defaultIndex[0], 2}, // Proof of presence.
		{defaultIndex[1], 2},
	}
	for _, test := range tests {
		nbrs, _ := m.Neighbors(ctx, H2B(test.hindex))
		if got, want := sqlhist.PrefixLen(nbrs), test.depth; got != want {
			t.Errorf("len(Neighbors(%v))=%v, want %v", test.hindex, got, want)
		}
	}
}

func TestFromNeighbors(t *testing.T) {
	f := NewFactory()
	trees := [][]struct {
		hindex string
		value  string
	}{
		{
			{defaultIndex[2], "0"},
			{defaultIndex[0], "3"},
		},
		{
			{defaultIndex[0], "3"},
			{defaultIndex[1], "4"},
		},
	}

	for _, leaves := range trees {
		m := New()
		for _, l := range leaves {
			m.WriteLeaf(ctx, H2B(l.hindex), []byte(l.value))
		}
		for i, tc := range leaves {
			index := H2B(tc.hindex)
			data := []byte(tc.value)

			// Recreate the tree from the neighbors and verify that the roots are equal.

			nbrs, _ := m.Neighbors(ctx, index)
			m2 := f.FromNeighbors(nbrs, index, data)

			r, _ := m.ReadRoot(ctx)
			r2, _ := m2.ReadRoot(ctx)

			if got, want := r2, r; !bytes.Equal(got, want) {
				t.Errorf("%v: FromNeighbors().Root=%v, want %v", i, got, want)

			}
		}
	}
}

// Hex to Bytes
func H2B(h string) []byte {
	result, err := hex.DecodeString(h)
	if err != nil {
		panic("DecodeString failed")
	}
	return result
}
