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
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	_ "github.com/mattn/go-sqlite3"
)

func newForTest(ctx context.Context, t testing.TB, logIDs ...int64) *Mutations {
	m, err := New(newDB(t))
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}
	if err := m.AddLogs(ctx, directoryID, logIDs...); err != nil {
		t.Fatalf("AddLogs(): %v", err)
	}
	return m
}

func TestRandLog(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		desc     string
		send     []int64
		wantCode codes.Code
		wantLogs map[int64]bool
	}{
		{desc: "no rows", wantCode: codes.NotFound, wantLogs: map[int64]bool{}},
		{desc: "one row", send: []int64{10}, wantLogs: map[int64]bool{10: true}},
		{desc: "second", send: []int64{1, 2, 3}, wantLogs: map[int64]bool{
			1: true,
			2: true,
			3: true,
		}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			m := newForTest(ctx, t, tc.send...)
			logs := make(map[int64]bool)
			for i := 0; i < 10*len(tc.wantLogs); i++ {
				logID, err := m.randLog(ctx, directoryID)
				if got, want := status.Code(err), tc.wantCode; got != want {
					t.Errorf("randLog(): %v, want %v", got, want)
				}
				if err != nil {
					break
				}
				logs[logID] = true
			}
			if got, want := logs, tc.wantLogs; !cmp.Equal(got, want) {
				t.Errorf("logs: %v, want %v", got, want)
			}
		})
	}
}

func BenchmarkSend(b *testing.B) {
	ctx := context.Background()
	logID := int64(1)
	m := newForTest(ctx, b, logID)

	update := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte("xxxxxxxxxxxxxxxxxx")}}
	for _, tc := range []struct {
		batch int
	}{
		{batch: 1},
		{batch: 2},
		{batch: 4},
		{batch: 8},
		{batch: 16},
		{batch: 32},
		{batch: 64},
		{batch: 128},
		{batch: 256},
	} {
		b.Run(fmt.Sprintf("%d", tc.batch), func(b *testing.B) {
			updates := make([]*pb.EntryUpdate, 0, tc.batch)
			for i := 0; i < tc.batch; i++ {
				updates = append(updates, update)
			}
			for n := 0; n < b.N; n++ {
				if _, err := m.Send(ctx, directoryID, updates...); err != nil {
					b.Errorf("Send(): %v", err)
				}
			}
		})
	}
}

func TestSend(t *testing.T) {
	ctx := context.Background()

	m := newForTest(ctx, t, 1, 2)
	update := []byte("bar")
	ts1 := time.Now()
	ts2 := ts1.Add(time.Duration(1))
	ts3 := ts2.Add(time.Duration(1))

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
		err := m.send(ctx, tc.ts, directoryID, 1, update, update)
		if got, want := status.Code(err), tc.wantCode; got != want {
			t.Errorf("%v: send(): %v, got: %v, want %v", tc.desc, err, got, want)
		}
	}
}

func TestWatermark(t *testing.T) {
	ctx := context.Background()
	logIDs := []int64{1, 2}
	m := newForTest(ctx, t, logIDs...)
	update := []byte("bar")

	startTS := time.Now()
	for ts := startTS; ts.Before(startTS.Add(10)); ts = ts.Add(1) {
		for _, logID := range logIDs {
			if err := m.send(ctx, ts, directoryID, logID, update); err != nil {
				t.Fatalf("m.send(%v): %v", logID, err)
			}
		}
	}

	start := startTS.UnixNano()
	for _, tc := range []struct {
		desc      string
		logID     int64
		start     int64
		batchSize int32
		count     int32
		want      int64
	}{
		{desc: "log1 max", logID: 1, batchSize: 100, want: start + 10, count: 10},
		{desc: "log2 max", logID: 2, batchSize: 100, want: start + 10, count: 10},
		{desc: "batch0", logID: 1, batchSize: 0},
		{desc: "batch0start55", logID: 1, start: 55, batchSize: 0, want: 55},
		{desc: "batch5", logID: 1, batchSize: 5, want: start + 5, count: 5},
		{desc: "start1", logID: 1, start: start + 2, batchSize: 5, want: start + 7, count: 5},
		{desc: "start8", logID: 1, start: start + 8, batchSize: 5, want: start + 10, count: 2},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, got, err := m.HighWatermark(ctx, directoryID, tc.logID, tc.start, tc.batchSize)
			if err != nil {
				t.Errorf("highWatermark(): %v", err)
			}
			if got != tc.want {
				t.Errorf("highWatermark(%v) high: %v, want %v", tc.start, got, tc.want)
			}
			if count != tc.count {
				t.Errorf("highWatermark(%v) count: %v, want %v", tc.start, count, tc.count)
			}
		})
	}
}

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(): %v", err)
	}
	return b
}

func TestReadLog(t *testing.T) {
	ctx := context.Background()
	logID := int64(5)
	m := newForTest(ctx, t, logID)
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		if _, err := m.Send(ctx, directoryID, entry, entry, entry); err != nil {
			t.Fatalf("Send(): %v", err)
		}
	}

	for _, tc := range []struct {
		batchSize int32
		count     int
	}{
		{batchSize: 0, count: 0},
		{batchSize: 1, count: 3},
		{batchSize: 4, count: 6},
		{batchSize: 100, count: 30},
	} {
		rows, err := m.ReadLog(ctx, directoryID, logID, 0, time.Now().UnixNano(), tc.batchSize)
		if err != nil {
			t.Fatalf("ReadLog(%v): %v", tc.batchSize, err)
		}
		if got, want := len(rows), tc.count; got != want {
			t.Fatalf("ReadLog(%v): len: %v, want %v", tc.batchSize, got, want)
		}
	}
}
