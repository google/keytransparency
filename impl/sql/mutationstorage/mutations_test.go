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

	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
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

func genUpdate(i int) *pb.EntryUpdate {
	return &pb.EntryUpdate{
		Mutation: &pb.Entry{
			Index:      []byte(fmt.Sprintf("index%d", i)),
			Commitment: []byte(fmt.Sprintf("mutation%d", i)),
		},
		Committed: &pb.Committed{
			Key:  []byte(fmt.Sprintf("nonce%d", i)),
			Data: []byte(fmt.Sprintf("data%d", i)),
		},
	}
}

func fillDB(ctx context.Context, t *testing.T, m mutator.MutationStorage) {
	for _, mtn := range []struct {
		update      *pb.EntryUpdate
		outSequence uint64
	}{
		{update: genUpdate(1), outSequence: 1},
		{update: genUpdate(2), outSequence: 2},
		{update: genUpdate(3), outSequence: 3},
		{update: genUpdate(4), outSequence: 4},
		{update: genUpdate(5), outSequence: 5},
	} {
		if err := write(ctx, m, mtn.update, mtn.outSequence); err != nil {
			t.Errorf("failed to write mutation to database, mutation=%v: %v", mtn.update, err)
		}
	}
}

func write(ctx context.Context, m mutator.MutationStorage, mutation *pb.EntryUpdate, outSequence uint64) error {
	sequence, err := m.Write(ctx, mapID, mutation)
	if err != nil {
		return fmt.Errorf("Write(%v): %v, want nil", mutation, err)
	}
	if got, want := sequence, outSequence; got != want {
		return fmt.Errorf("Write(%v)=%v, want %v", mutation, got, want)
	}

	return nil
}

func TestReadRange(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		endSequence   uint64
		count         int32
		maxSequence   uint64
		mutations     []*pb.EntryUpdate
	}{
		{
			description: "read a single mutation",
			endSequence: 1,
			count:       1,
			maxSequence: 1,
			mutations:   []*pb.EntryUpdate{genUpdate(1)},
		},
		{
			description:   "empty mutations list",
			startSequence: 100,
			endSequence:   110,
			count:         10,
		},
		{
			description:   "full mutations range size",
			startSequence: 0,
			endSequence:   5,
			count:         5,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(1),
				genUpdate(2),
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
		},
		{
			description:   "incomplete mutations range",
			startSequence: 2,
			endSequence:   5,
			count:         3,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
		},
		{
			description:   "end sequence less than count",
			startSequence: 2,
			endSequence:   5,
			count:         5,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
		},
		{
			description: "count less than end sequence",
			endSequence: 5,
			count:       3,
			maxSequence: 3,
			mutations: []*pb.EntryUpdate{
				genUpdate(1),
				genUpdate(2),
				genUpdate(3),
			},
		},
	} {
		maxSequence, results, err := m.ReadRange(ctx, mapID, tc.startSequence, tc.endSequence, tc.count)
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
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m)

	for _, tc := range []struct {
		description   string
		startSequence uint64
		maxSequence   uint64
		mutations     []*pb.EntryUpdate
	}{
		{
			description:   "empty mutations list",
			startSequence: 100,
			maxSequence:   0,
			mutations:     nil,
		},
		{
			description:   "read all mutations",
			startSequence: 0,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(1),
				genUpdate(2),
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
		},
		{
			description:   "read half of the mutations",
			startSequence: 2,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
		},
		{
			description:   "read last mutation",
			startSequence: 4,
			maxSequence:   5,
			mutations: []*pb.EntryUpdate{
				genUpdate(5),
			},
		},
	} {
		maxcount := 1000
		maxSequence, results, err := m.ReadAll(ctx, mapID, tc.startSequence, maxcount)
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
