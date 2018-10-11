// Copyright 2018 Google Inc. All Rights Reserved.
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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	_ "github.com/mattn/go-sqlite3"
)

func TestRandShard(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}

	for _, tc := range []struct {
		desc       string
		send       []int64
		wantCode   codes.Code
		wantShards map[int64]bool
	}{
		{desc: "no rows", wantCode: codes.NotFound, wantShards: map[int64]bool{}},
		{desc: "second", send: []int64{1, 2, 3}, wantShards: map[int64]bool{
			1: true,
			2: true,
			3: true,
		}},
	} {
		if err := m.AddShards(ctx, domainID, tc.send...); err != nil {
			t.Fatalf("AddShards(): %v", err)
		}
		shards := make(map[int64]bool)
		for i := 0; i < 10*len(tc.wantShards); i++ {
			shard, err := m.randShard(ctx, domainID)
			if got, want := status.Code(err), tc.wantCode; got != want {
				t.Errorf("randShard(): %v, want %v", got, want)
			}
			if err != nil {
				break
			}
			shards[shard] = true
		}
		if got, want := shards, tc.wantShards; !cmp.Equal(got, want) {
			t.Errorf("shards: %v, want %v", got, want)
		}
	}
}

func TestSend(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}
	update := []byte("bar")
	ts1 := time.Now()
	ts2 := ts1.Add(time.Duration(1))
	ts3 := ts2.Add(time.Duration(1))

	if err := m.AddShards(ctx, domainID, 1, 2); err != nil {
		t.Fatalf("AddShards(): %v", err)
	}

	// Test cases are cumulative. Earlier test caes setup later test cases.
	for _, tc := range []struct {
		desc     string
		ts       time.Time
		wantCode codes.Code
	}{
		// Enforce timestamp uniqueness.
		{desc: "First", ts: ts2},
		{desc: "Second", ts: ts2, wantCode: codes.Aborted},
		// Enforce a monotonically increasing timestamp
		{desc: "Old", ts: ts1, wantCode: codes.Aborted},
		{desc: "New", ts: ts3},
	} {
		err := m.send(ctx, domainID, 1, update, tc.ts)
		if got, want := status.Code(err), tc.wantCode; got != want {
			t.Errorf("%v: send(): %v, got: %v, want %v", tc.desc, err, got, want)
		}
	}
}

func TestWatermarks(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}
	ts1 := time.Now()
	ts2 := ts1.Add(time.Duration(1))

	if err := m.AddShards(ctx, domainID, 1, 2, 3); err != nil {
		t.Fatalf("AddShards(): %v", err)
	}

	for _, tc := range []struct {
		desc string
		send map[int64]time.Time
		want map[int64]int64
	}{
		{desc: "no rows", want: map[int64]int64{}},
		{
			desc: "first",
			send: map[int64]time.Time{1: ts1},
			want: map[int64]int64{1: ts1.UnixNano()},
		},
		{
			desc: "second",
			// Highwatermarks in each shard proceed independently.
			send: map[int64]time.Time{1: ts2, 2: ts1},
			want: map[int64]int64{1: ts2.UnixNano(), 2: ts1.UnixNano()},
		},
	} {
		for shardID, ts := range tc.send {
			if err := m.send(ctx, domainID, shardID, []byte("mutation"), ts); err != nil {
				t.Fatalf("send(%v, %v): %v", shardID, ts, err)
			}
		}
		highs, err := m.HighWatermarks(ctx, domainID)
		if err != nil {
			t.Fatalf("HighWatermark(): %v", err)
		}
		if !cmp.Equal(highs, tc.want) {
			t.Errorf("HighWatermark(): %v, want %v", highs, tc.want)
		}
	}
}

func TestReadQueue(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	shardID := int64(5)
	if err := m.AddShards(ctx, domainID, shardID); err != nil {
		t.Fatalf("AddShards(): %v", err)
	}
	if err := m.Send(ctx, domainID, &pb.EntryUpdate{}); err != nil {
		t.Fatalf("Send(): %v", err)
	}

	rows, err := m.ReadQueue(ctx, domainID, shardID, 0, time.Now().UnixNano())
	if err != nil {
		t.Fatalf("ReadQueue(): %v", err)
	}
	if got, want := len(rows), 1; got != want {
		t.Fatalf("ReadQueue(): len: %v, want %v", got, want)
	}
}
