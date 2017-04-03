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

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
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
		mutation    *tpb.SignedKV
		outSequence uint64
	}{
		{
			&tpb.SignedKV{
				KeyValue: &tpb.KeyValue{
					Key:   []byte("index1"),
					Value: []byte("mutation1"),
				},
			},
			1,
		},
		{
			&tpb.SignedKV{
				KeyValue: &tpb.KeyValue{
					Key:   []byte("index2"),
					Value: []byte("mutation2"),
				},
			},
			2,
		},
		{
			&tpb.SignedKV{
				KeyValue: &tpb.KeyValue{
					Key:   []byte("index3"),
					Value: []byte("mutation3"),
				},
			},
			3,
		},
		{
			&tpb.SignedKV{
				KeyValue: &tpb.KeyValue{
					Key:   []byte("index4"),
					Value: []byte("mutation4"),
				},
			},
			4,
		},
		{
			&tpb.SignedKV{
				KeyValue: &tpb.KeyValue{
					Key:   []byte("index5"),
					Value: []byte("mutation5"),
				},
			},
			5,
		},
	} {
		if err := write(ctx, m, factory, mtn.mutation, mtn.outSequence); err != nil {
			t.Errorf("failed to write mutation to database, mutation=%v: %v", mtn.mutation, err)
		}
	}
}

func write(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, mutation *tpb.SignedKV, outSequence uint64) error {
	wtxn, err := factory.NewDBTxn(ctx)
	if err != nil {
		return fmt.Errorf("failed to create write transaction: %v", err)
	}
	sequence, err := m.Write(wtxn, mutation)
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

func read(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, startSequence uint64, count int) ([]*tpb.SignedKV, error) {
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
	fillDB(ctx, t, m, factory)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		count         int
		mutations     []*tpb.SignedKV
	}{
		{
			"read a single mutation",
			1,
			1,
			[]*tpb.SignedKV{
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index1"),
						Value: []byte("mutation1"),
					},
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
			[]*tpb.SignedKV{
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index1"),
						Value: []byte("mutation1"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index2"),
						Value: []byte("mutation2"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index3"),
						Value: []byte("mutation3"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index4"),
						Value: []byte("mutation4"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index5"),
						Value: []byte("mutation5"),
					},
				},
			},
		},
		{
			"incomplete mutations range",
			3,
			5,
			[]*tpb.SignedKV{
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index3"),
						Value: []byte("mutation3"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index4"),
						Value: []byte("mutation4"),
					},
				},
				{
					KeyValue: &tpb.KeyValue{
						Key:   []byte("index5"),
						Value: []byte("mutation5"),
					},
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
			if got, want := results[i].GetKeyValue().Key, tc.mutations[i].GetKeyValue().Key; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: results[%v] index=%v, want %v", tc.description, i, got, want)
			}
			if got, want := results[i].GetKeyValue().Value, tc.mutations[i].GetKeyValue().Value; !reflect.DeepEqual(got, want) {
				t.Errorf("%v: results[%v] data=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}
