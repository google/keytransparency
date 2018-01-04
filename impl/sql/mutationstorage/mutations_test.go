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

	"github.com/google/go-cmp/cmp"
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

func genUpdate(i int) *mutator.QueueMessage {
	return &mutator.QueueMessage{
		ID: int64(i),
		Mutation: &pb.Entry{
			Index:      []byte(fmt.Sprintf("index%d", i)),
			Commitment: []byte(fmt.Sprintf("mutation%d", i)),
		},
		ExtraData: &pb.Committed{
			Key:  []byte(fmt.Sprintf("nonce%d", i)),
			Data: []byte(fmt.Sprintf("data%d", i)),
		},
	}
}

func fillDB(ctx context.Context, t *testing.T, m mutator.MutationStorage) {
	for _, mtn := range []struct {
		update      *mutator.QueueMessage
		outSequence int64
	}{
		{update: genUpdate(1), outSequence: 1},
		{update: genUpdate(2), outSequence: 2},
		{update: genUpdate(3), outSequence: 3},
		{update: genUpdate(4), outSequence: 4},
		{update: genUpdate(5), outSequence: 5},
	} {
		if err := write(ctx, m, &pb.EntryUpdate{
			Mutation:  mtn.update.Mutation,
			Committed: mtn.update.ExtraData,
		}, mtn.outSequence); err != nil {
			t.Errorf("failed to write mutation to database, mutation=%v: %v", mtn.update, err)
		}
	}
}

func write(ctx context.Context, m mutator.MutationStorage, mutation *pb.EntryUpdate, outSequence int64) error {
	sequence, err := m.Write(ctx, mapID, mutation)
	if err != nil {
		return fmt.Errorf("Write(%v): %v, want nil", mutation, err)
	}
	if got, want := sequence, outSequence; got != want {
		return fmt.Errorf("Write(%v)=%v, want %v", mutation, got, want)
	}

	return nil
}

func TestReadPage(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m)

	for _, tc := range []struct {
		description   string
		startSequence int64
		endSequence   int64
		count         int32
		maxSequence   int64
		mutations     []*pb.Entry
	}{
		{
			description: "read a single mutation",
			endSequence: 1,
			count:       1,
			maxSequence: 1,
			mutations:   []*pb.Entry{genUpdate(1).Mutation},
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
			mutations: []*pb.Entry{
				genUpdate(1).Mutation,
				genUpdate(2).Mutation,
				genUpdate(3).Mutation,
				genUpdate(4).Mutation,
				genUpdate(5).Mutation,
			},
		},
		{
			description:   "incomplete mutations range",
			startSequence: 2,
			endSequence:   5,
			count:         3,
			maxSequence:   5,
			mutations: []*pb.Entry{
				genUpdate(3).Mutation,
				genUpdate(4).Mutation,
				genUpdate(5).Mutation,
			},
		},
		{
			description:   "end sequence less than count",
			startSequence: 2,
			endSequence:   5,
			count:         5,
			maxSequence:   5,
			mutations: []*pb.Entry{
				genUpdate(3).Mutation,
				genUpdate(4).Mutation,
				genUpdate(5).Mutation,
			},
		},
		{
			description: "count less than end sequence",
			endSequence: 5,
			count:       3,
			maxSequence: 3,
			mutations: []*pb.Entry{
				genUpdate(1).Mutation,
				genUpdate(2).Mutation,
				genUpdate(3).Mutation,
			},
		},
	} {
		maxSequence, results, err := m.ReadPage(ctx, mapID, tc.startSequence, tc.endSequence, tc.count)
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

func TestReadBatch(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(ctx, t, m)

	for _, tc := range []struct {
		description   string
		startSequence int64
		maxSequence   int64
		mutations     []*mutator.QueueMessage
		batchSize     int32
	}{
		{
			description:   "empty mutations list",
			startSequence: 100,
			maxSequence:   0,
			mutations:     nil,
			batchSize:     10,
		},
		{
			description:   "read all mutations",
			startSequence: 0,
			maxSequence:   5,
			mutations: []*mutator.QueueMessage{
				genUpdate(1),
				genUpdate(2),
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
			batchSize: 10,
		},
		{
			description:   "read half of the mutations",
			startSequence: 2,
			maxSequence:   5,
			mutations: []*mutator.QueueMessage{
				genUpdate(3),
				genUpdate(4),
				genUpdate(5),
			},
			batchSize: 10,
		},
		{
			description:   "limit by batch",
			startSequence: 2,
			maxSequence:   3,
			mutations: []*mutator.QueueMessage{
				genUpdate(3),
			},
			batchSize: 1,
		},
		{
			description:   "read last mutation",
			startSequence: 4,
			maxSequence:   5,
			mutations: []*mutator.QueueMessage{
				genUpdate(5),
			},
			batchSize: 10,
		},
	} {
		maxSequence, results, err := m.ReadBatch(ctx, mapID, tc.startSequence, tc.batchSize)
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
			if got, want := results[i], tc.mutations[i]; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("%v: results[%v] data=%v, want %v", tc.description, i, got, want)
			}
		}
	}
}
