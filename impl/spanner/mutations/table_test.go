// Copyright 2020 Google Inc. All Rights Reserved.
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
	"fmt"
	"testing"
	"time"

	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/impl/spanner/directory"
	"github.com/google/keytransparency/impl/spanner/testutil"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	dtype "github.com/google/keytransparency/core/directory"
	ktspanner "github.com/google/keytransparency/impl/spanner"
	tpb "github.com/google/trillian"
)

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Errorf("proto.Marshal(): %v", err)
	}
	return b
}

func NewForTest(ctx context.Context, t testing.TB, dirID string, logIDs ...int64) *Table {
	t.Helper()
	ddl, err := ktspanner.ReadDDL()
	if err != nil {
		t.Fatal(err)
	}
	client := testutil.CreateDatabase(ctx, t, ddl)
	q := New(client)

	if err := directory.New(client).Write(ctx, &dtype.Directory{
		DirectoryID: dirID,
		Map:         &tpb.Tree{},
		Log:         &tpb.Tree{},
		VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
	}); err != nil {
		t.Fatalf("directories.Write(%v): %v", dirID, err)
	}
	if err := q.AddLogs(ctx, dirID, logIDs...); err != nil {
		t.Fatalf("AddLogs(): %v", err)
	}
	time.Sleep(readStaleness)

	return q
}

func TestNewForTest(t *testing.T) {
	ctx := context.Background()
	NewForTest(ctx, t, "newfortest", 1)
}

func TestMutationLogsIntegration(t *testing.T) {
	t.Parallel()
	storagetest.RunMutationLogsTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) keyserver.MutationLogs {
			return NewForTest(ctx, t, dirID, logIDs...)
		})
}

func TestLogsAdminIntegration(t *testing.T) {
	t.Parallel()
	storagetest.RunLogsAdminTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) adminserver.LogsAdmin {
			return NewForTest(ctx, t, dirID, logIDs...)
		})
}

func TestReadBatch(t *testing.T) {
	t.Parallel()
	const dirID = "readbatch"
	ctx := context.Background()
	logID := int64(5)
	m := NewForTest(ctx, t, dirID, logID)
	var lastTS water.Mark
	var err error
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		batch := []*pb.EntryUpdate{entry, entry, entry}
		lastTS, err = m.SendBatch(ctx, dirID, logID, batch)
		if err != nil {
			t.Fatalf("Send(): %v", err)
		}
	}

	for _, tc := range []struct {
		batchSize int32
		count     int
	}{
		{batchSize: 0, count: 0},
		{batchSize: 1, count: 3},
		{batchSize: 3, count: 3},
		{batchSize: 4, count: 6}, // A partial read into the next timestamp returns all rows in the timestamp.
		{batchSize: 100, count: 30},
	} {
		rows, err := m.ReadLog(ctx, dirID, logID, water.NewMark(0), lastTS.Add(1), tc.batchSize)
		if err != nil {
			t.Fatalf("ReadLog(): %v", err)
		}
		if got, want := len(rows), tc.count; got != want {
			t.Fatalf("ReadLog(%v): len: %v, want %v", tc.batchSize, got, want)
		}
	}
}

func TestReadLog(t *testing.T) {
	t.Parallel()
	const dirID = "readlog"
	ctx := context.Background()
	logID := int64(1)
	q := NewForTest(ctx, t, dirID, logID)

	ts1, err := q.SendBatch(ctx, dirID, logID, []*pb.EntryUpdate{{}})
	if err != nil {
		t.Fatalf("Send(): %v", err)
	}
	for _, tc := range []struct {
		desc      string
		low, high water.Mark
		want      int
	}{
		// {desc: "read nothing", low: ts1, high: ts1, want: 0}, // Not supported by Cloud Spanner
		{desc: "open end", high: ts1, want: 0},
		{desc: "exact timestamp", low: ts1, high: ts1.Add(1), want: 1},
		{desc: "don't read ahead", high: ts1, want: 0},
		{desc: "sanity check", high: ts1.Add(1), want: 1},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			batchSize := int32(1000)
			rows, err := q.ReadLog(ctx, dirID, 1, tc.low, tc.high, batchSize)
			if err != nil {
				t.Fatalf("ReadLog(): %v", err)
			}
			if got := len(rows); got != tc.want {
				t.Logf("Send(): %v", ts1)
				t.Errorf("ReadLog(%v, %v): len: %v, want %v", tc.low, tc.high, got, tc.want)
			}
		})
	}
}

func TestWatermark(t *testing.T) {
	t.Parallel()
	const dirID = "watermark"
	ctx := context.Background()
	logIDs := []int64{1, 2}
	m := NewForTest(ctx, t, dirID, logIDs...)

	marks := make(map[int64][]water.Mark)
	for _, logID := range logIDs {
		marks[logID] = []water.Mark{}
		for i := 0; i < 10; i++ {
			ts, err := m.SendBatch(ctx, dirID, logID, []*pb.EntryUpdate{{}})
			if err != nil {
				t.Fatalf("m.Send(%v): %v", logID, err)
			}
			marks[logID] = append(marks[logID], ts)
		}
	}

	for _, tc := range []struct {
		desc      string
		logID     int64
		start     water.Mark
		batchSize int32
		count     int32
		want      water.Mark
	}{
		{desc: "log1 max", logID: 1, batchSize: 100, want: marks[1][9].Add(1), count: 10},
		{desc: "log2 max", logID: 2, batchSize: 100, want: marks[2][9].Add(1), count: 10},
		{desc: "batch0", logID: 1, batchSize: 0, want: water.NewMark(0)},
		{desc: "batch0start55", logID: 1, start: water.NewMark(55), batchSize: 0, want: water.NewMark(55)},
		{desc: "batch5", logID: 1, batchSize: 5, want: marks[1][4].Add(1), count: 5},
		{desc: "start1", logID: 1, start: marks[1][2], batchSize: 5, want: marks[1][6].Add(1), count: 5},
		{desc: "start8", logID: 1, start: marks[1][8], batchSize: 5, want: marks[1][9].Add(1), count: 2},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, got, err := m.HighWatermark(ctx, dirID, tc.logID, tc.start, tc.batchSize)
			if err != nil {
				t.Errorf("HighWatermark(): %v", err)
			}
			if got != tc.want {
				t.Errorf("HighWatermark(%v) high: %v, want %v", tc.start, got, tc.want)
			}
			if count != tc.count {
				t.Errorf("HighWatermark(%v) count: %v, want %v", tc.start, count, tc.count)
			}
		})
	}
}

func TestEnqueue(t *testing.T) {
	t.Parallel()
	const dirID = "enqueue"
	const logID = int64(1)
	ctx := context.Background()
	q := NewForTest(ctx, t, dirID, logID)
	if _, err := q.SendBatch(ctx, dirID, logID, []*pb.EntryUpdate{{
		Mutation: &pb.SignedEntry{
			Entry: mustMarshal(t, &pb.Entry{Index: []byte("index")}),
		}}}); err != nil {
		t.Errorf("Send(): %v", err)
	}
}

func BenchmarkSend(b *testing.B) {
	const dirID = "benchmarksend"
	ctx := context.Background()
	logID := int64(1)
	m := NewForTest(ctx, b, dirID, logID)
	update := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte("xxxxxxxxxxxxxxxxxx")}}
	for batch := 1; batch < 1024; batch *= 2 {
		b.Run(fmt.Sprintf("%d", batch), func(b *testing.B) {
			updates := make([]*pb.EntryUpdate, 0, batch)
			for i := 0; i < batch; i++ {
				updates = append(updates, update)
			}
			for n := 0; n < b.N; n++ {
				if _, err := m.SendBatch(ctx, dirID, logID, updates); err != nil {
					b.Errorf("Send(): %v", err)
				}
			}
		})
	}
}
