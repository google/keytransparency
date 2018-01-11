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

const domainID = "default"

func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func genMutation(i int) *pb.Entry {
	return &pb.Entry{
		Index:      []byte(fmt.Sprintf("index%d", i)),
		Commitment: []byte(fmt.Sprintf("mutation%d", i)),
	}
}

func fillDB(ctx context.Context, m mutator.MutationStorage) error {
	for _, tc := range []struct {
		revision  int64
		mutations []*pb.Entry
	}{
		{
			revision: 0,
			mutations: []*pb.Entry{
				genMutation(1),
				genMutation(2),
			},
		},
		{
			revision: 1,
			mutations: []*pb.Entry{
				genMutation(3),
				genMutation(4),
				genMutation(5),
			},
		},
	} {
		if err := m.WriteBatch(ctx, domainID, tc.revision, tc.mutations); err != nil {
			return err
		}
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
	if err := fillDB(ctx, m); err != nil {
		t.Fatalf("Failed to write mutations: %v", err)
	}

	for _, tc := range []struct {
		description string
		revision    int64
		start       int64
		count       int32
		wantMax     int64
		mutations   []*pb.Entry
	}{
		{
			description: "read a single mutation",
			start:       0,
			count:       1,
			wantMax:     0,
			mutations:   []*pb.Entry{genMutation(1)},
		},
		{
			description: "empty mutations list",
			revision:    100,
			start:       0,
			count:       10,
		},
		{
			description: "full mutations range size",
			revision:    0,
			start:       0,
			count:       5,
			wantMax:     1,
			mutations: []*pb.Entry{
				genMutation(1),
				genMutation(2),
			},
		},
		{
			description: "non-zero start",
			revision:    1,
			start:       1,
			count:       2,
			wantMax:     2,
			mutations: []*pb.Entry{
				genMutation(4),
				genMutation(5),
			},
		},
		{
			description: "limit by count",
			revision:    1,
			start:       0,
			count:       2,
			wantMax:     1,
			mutations: []*pb.Entry{
				genMutation(3),
				genMutation(4),
			},
		},
	} {
		t.Run(tc.description, func(t *testing.T) {
			max, results, err := m.ReadPage(ctx, domainID, tc.revision, tc.start, tc.count)
			if err != nil {
				t.Errorf("failed to read mutations: %v", err)
			}
			if got, want := max, tc.wantMax; got != want {
				t.Errorf("ReadPage(%v,%v,%v).max:%v, want %v", tc.revision, tc.start, tc.count, got, want)
			}
			if got, want := len(results), len(tc.mutations); got != want {
				t.Fatalf("len(results)=%v, want %v", got, want)
			}
			for i := range results {
				if got, want := results[i], tc.mutations[i]; !proto.Equal(got, want) {
					t.Errorf("results[%v] data=%v, want %v", i, got, want)
				}
			}
		})
	}
}
