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
	"fmt"
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/impl/sql/testutil"
	_ "github.com/mattn/go-sqlite3"
)

const mapID = 0

func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func fillDB(t *testing.T, ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory) {
	for _, mtn := range []struct {
		index       []byte
		mutation    []byte
		outSequence uint64
	}{
		{[]byte("index1"), []byte("mutation1"), 1},
		{[]byte("index2"), []byte("mutation2"), 2},
		{[]byte("index3"), []byte("mutation3"), 3},
		{[]byte("index4"), []byte("mutation4"), 4},
		{[]byte("index5"), []byte("mutation5"), 5},
	} {
		if err := write(ctx, m, factory, mtn.index, mtn.mutation, mtn.outSequence); err != nil {
			t.Errorf("failed to write mutation to database, mutation=%v, mutation=%v: %v", mtn.index, mtn.mutation, err)
		}
	}
}

func write(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, index []byte, mutation []byte, outSequence uint64) error {
	wtxn, err := factory.NewDBTxn(ctx)
	if err != nil {
		return fmt.Errorf("failed to create write transaction: %v", err)
	}
	sequence, err := m.Write(wtxn, index, mutation)
	if err != nil {
		return fmt.Errorf("Write(%v, %v): %v, want nil", index, mutation, err)
	}
	if err := wtxn.Commit(); err != nil {
		return fmt.Errorf("wtxn.Commit() failed: %v", err)
	}
	if got, want := sequence, outSequence; got != want {
		return fmt.Errorf("Write(%v, %v)=%v, want %v", index, mutation, got, want)
	}

	return nil
}

func read(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, startSequence uint64, count int) ([]mutator.MutationInfo, error) {
	rtxn, err := factory.NewDBTxn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create read transaction: %v", err)
	}
	results, err := m.ReadRange(rtxn, startSequence, count)
	if err != nil {
		return nil, fmt.Errorf("ReadRange(%v, %v): %v, want nil", startSequence, count, err)
	}
	if err := rtxn.Commit(); err != nil {
		return nil, fmt.Errorf("rtxn.Commit() failed: %v", err)
	}
	return results, nil
}

func TestReadRange(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db, mapID)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(t, ctx, m, factory)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		count         int
		mutations     []mutator.MutationInfo
	}{
		{
			"read a single mutation",
			1,
			1,
			[]mutator.MutationInfo{
				{
					Index: []byte("index1"),
					Data:  []byte("mutation1"),
				},
			},
		},
		{
			"empty mutation info list",
			100,
			10,
			nil,
		},
		{
			"full mutations range size",
			1,
			5,
			[]mutator.MutationInfo{
				{
					Index: []byte("index1"),
					Data:  []byte("mutation1"),
				},
				{
					Index: []byte("index2"),
					Data:  []byte("mutation2"),
				},
				{
					Index: []byte("index3"),
					Data:  []byte("mutation3"),
				},
				{
					Index: []byte("index4"),
					Data:  []byte("mutation4"),
				},
				{
					Index: []byte("index5"),
					Data:  []byte("mutation5"),
				},
			},
		},
		{
			"incomplete mutations range",
			3,
			5,
			[]mutator.MutationInfo{
				{
					Index: []byte("index3"),
					Data:  []byte("mutation3"),
				},
				{
					Index: []byte("index4"),
					Data:  []byte("mutation4"),
				},
				{
					Index: []byte("index5"),
					Data:  []byte("mutation5"),
				},
			},
		},
	} {
		results, err := read(ctx, m, factory, tc.startSequence, tc.count)
		if err != nil {
			t.Errorf("%v: failed to read mutations: %v", tc.description, err)
		}
		if got, want := len(results), len(tc.mutations); got != want {
			t.Errorf("%v: len(results)=%v, want %v", tc.description, got, want)
			continue
		}
		for i := range results {
			if got, want := results[i].Index, tc.mutations[i].Index; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: results[%v].Index=%v, want %v", tc.description, i, got, want)
			}
			if got, want := results[i].Data, tc.mutations[i].Data; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: results[%v].Data=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}
