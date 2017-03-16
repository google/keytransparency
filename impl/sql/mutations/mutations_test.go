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
package mutations

import (
	"context"
	"database/sql"
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/impl/sql/testutil"
	_ "github.com/mattn/go-sqlite3"
)

const (
	mapID = "test"
)

func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func fillDB(t *testing.T, ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory) {
	for _, mtn := range []struct {
		epoch    int64
		index    []byte
		mutation []byte
	}{
		{1, []byte("index1"), []byte("mutation1")},
		{2, []byte("index2"), []byte("mutation2")},
		{2, []byte("index2"), []byte("mutation3")},
	} {
		wtxn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("failed to create write transaction: %v", err)
			continue
		}
		if err := m.Write(ctx, wtxn, mtn.epoch, mtn.index, mtn.mutation); err != nil {
			t.Errorf("Write(%v, %v, %v): %v, want nil", mtn.epoch, mtn.index, mtn.mutation, err)
		}
		if err := wtxn.Commit(); err != nil {
			t.Errorf("wtxn.Commit() failed: %v", err)
		}
	}
}

func TestRead(t *testing.T) {
	ctx := context.Background()
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db, mapID)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(t, ctx, m, factory)

	for _, tc := range []struct {
		description string
		epoch       int64
		index       []byte
		mutations   [][]byte
	}{
		{"read a single mutation", 1, []byte("index1"), [][]byte{[]byte("mutation1")}},
		{"read multiple mutations", 2, []byte("index2"), [][]byte{[]byte("mutation2"), []byte("mutation3")}},
		{"non-existing epoch", 100, []byte("index1"), [][]byte{}},
		{"non-existing index", 1, []byte("index100"), [][]byte{}},
	} {
		rtxn, err := factory.NewDBTxn(ctx)
		if err != nil {
			t.Errorf("failed %v: to create write transaction: %v", tc.description, err)
			continue
		}
		ms, err := m.Read(ctx, rtxn, tc.epoch, tc.index)
		if err != nil {
			t.Errorf("%v: Read(%v, %v): %v, want nil", tc.description, tc.epoch, tc.index, err)
		}
		if err := rtxn.Commit(); err != nil {
			t.Errorf("%v: rtxn.Commit() failed: %v", tc.description, err)
		}
		if got, want := len(ms), len(tc.mutations); got != want {
			t.Errorf("%v: len(ms)=%v, want %v", tc.description, got, want)
		}
		for i := 0; i < len(ms); i++ {
			if got, want := ms[i], tc.mutations[i]; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: ms[%v]=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}
