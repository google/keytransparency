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
package mutationstorage

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/impl/sql/testutil"

	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
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

func fillDB(ctx context.Context, t *testing.T, m mutator.Mutation, factory *testutil.FakeFactory) {
	for _, mtn := range []struct {
		mutation    *tpb.Entry
		outSequence uint64
	}{
		{
			&tpb.Entry{
				Index:      []byte("index1"),
				Commitment: []byte("mutation1"),
			},
			1,
		},
		{
			&tpb.Entry{
				Index:      []byte("index2"),
				Commitment: []byte("mutation2"),
			},
			2,
		},
		{
			&tpb.Entry{
				Index:      []byte("index3"),
				Commitment: []byte("mutation3"),
			},
			3,
		},
		{
			&tpb.Entry{
				Index:      []byte("index4"),
				Commitment: []byte("mutation4"),
			},
			4,
		},
		{
			&tpb.Entry{
				Index:      []byte("index5"),
				Commitment: []byte("mutation5"),
			},
			5,
		},
	} {
		if err := write(ctx, m, factory, mtn.mutation, mtn.outSequence); err != nil {
			t.Errorf("failed to write mutation to database, mutation=%v: %v", mtn.mutation, err)
		}
	}
}

func write(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, mutation *tpb.Entry, outSequence uint64) error {
	wtxn, err := factory.NewTxn(ctx)
	if err != nil {
		return fmt.Errorf("failed to create write transaction: %v", err)
	}
	sequence, err := m.Write(wtxn, mapID, mutation)
	if err != nil {
		return fmt.Errorf("Write(%v): %v, want nil", mutation, err)
	}
	if err := wtxn.Commit(); err != nil {
		return fmt.Errorf("wtxn.Commit() failed: %v", err)
	}
	if got, want := sequence, outSequence; got != want {
		return fmt.Errorf("Write(%v)=%v, want %v", mutation, got, want)
	}

	return nil
}

func readRange(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, startSequence uint64, endSequence uint64, count int32) (uint64, []*tpb.Entry, error) {
	rtxn, err := factory.NewTxn(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create read transaction: %v", err)
	}
	maxSequence, results, err := m.ReadRange(rtxn, mapID, startSequence, endSequence, count)
	if err != nil {
		return 0, nil, fmt.Errorf("ReadRange(%v, %v): %v, want nil", startSequence, count, err)
	}
	if err := rtxn.Commit(); err != nil {
		return 0, nil, fmt.Errorf("rtxn.Commit() failed: %v", err)
	}
	return maxSequence, results, nil
}

func readAll(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, startSequence uint64) (uint64, []*tpb.Entry, error) {
	rtxn, err := factory.NewTxn(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to create read transaction: %v", err)
	}
	maxSequence, results, err := m.ReadAll(rtxn, mapID, startSequence)
	if err != nil {
		return 0, nil, fmt.Errorf("ReadRange(%v): %v, want nil", startSequence, err)
	}
	if err := rtxn.Commit(); err != nil {
		return 0, nil, fmt.Errorf("rtxn.Commit() failed: %v", err)
	}
	return maxSequence, results, nil
}

func TestReadRange(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m, factory)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		endSequence   uint64
		count         int32
		maxSequence   uint64
		mutations     []*tpb.Entry
	}{
		{
			"read a single mutation",
			0,
			1,
			1,
			1,
			[]*tpb.Entry{
				{
					Index:      []byte("index1"),
					Commitment: []byte("mutation1"),
				},
			},
		},
		{
			"empty mutations list",
			100,
			110,
			10,
			0,
			nil,
		},
		{
			"full mutations range size",
			0,
			5,
			5,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index1"),
					Commitment: []byte("mutation1"),
				},
				{
					Index:      []byte("index2"),
					Commitment: []byte("mutation2"),
				},
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
				{
					Index:      []byte("index4"),
					Commitment: []byte("mutation4"),
				},
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
		{
			"incomplete mutations range",
			2,
			5,
			3,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
				{
					Index:      []byte("index4"),
					Commitment: []byte("mutation4"),
				},
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
		{
			"end sequence less than count",
			2,
			5,
			5,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
				{
					Index:      []byte("index4"),
					Commitment: []byte("mutation4"),
				},
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
		{
			"count less than end sequence",
			0,
			5,
			3,
			3,
			[]*tpb.Entry{
				{
					Index:      []byte("index1"),
					Commitment: []byte("mutation1"),
				},
				{
					Index:      []byte("index2"),
					Commitment: []byte("mutation2"),
				},
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
			},
		},
	} {
		maxSequence, results, err := readRange(ctx, m, factory, tc.startSequence, tc.endSequence, tc.count)
		if err != nil {
			t.Errorf("%v: failed to read mutations: %v", tc.description, err)
		}
		if got, want := maxSequence, tc.maxSequence; got != want {
			t.Errorf("%v: maxSequence=%v, want %v", tc.description, got, want)
		}
		if got, want := len(results), len(tc.mutations); got != want {
			t.Errorf("%v: len(results)=%v, want %v", tc.description, got, want)
			continue
		}
		for i := range results {
			if got, want := results[i], tc.mutations[i]; !proto.Equal(got, want) {
				t.Errorf("%v: results[%v] data=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}

func TestReadAll(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m, factory)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		maxSequence   uint64
		mutations     []*tpb.Entry
	}{
		{
			"empty mutations list",
			100,
			0,
			nil,
		},
		{
			"read all mutations",
			0,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index1"),
					Commitment: []byte("mutation1"),
				},
				{
					Index:      []byte("index2"),
					Commitment: []byte("mutation2"),
				},
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
				{
					Index:      []byte("index4"),
					Commitment: []byte("mutation4"),
				},
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
		{
			"read half of the mutations",
			2,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index3"),
					Commitment: []byte("mutation3"),
				},
				{
					Index:      []byte("index4"),
					Commitment: []byte("mutation4"),
				},
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
		{
			"read last mutation",
			4,
			5,
			[]*tpb.Entry{
				{
					Index:      []byte("index5"),
					Commitment: []byte("mutation5"),
				},
			},
		},
	} {
		maxSequence, results, err := readAll(ctx, m, factory, tc.startSequence)
		if err != nil {
			t.Errorf("%v: failed to read mutations: %v", tc.description, err)
		}
		if got, want := maxSequence, tc.maxSequence; got != want {
			t.Errorf("%v: maxSequence=%v, want %v", tc.description, got, want)
		}
		if got, want := len(results), len(tc.mutations); got != want {
			t.Errorf("%v: len(results)=%v, want %v", tc.description, got, want)
			continue
		}
		for i := range results {
			if got, want := results[i], tc.mutations[i]; !proto.Equal(got, want) {
				t.Errorf("%v: results[%v] data=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}
