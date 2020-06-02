// Copyright 2019 Google Inc. All Rights Reserved.
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

package storagetest

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/water"
	"golang.org/x/sync/errgroup"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// mutationLogsFactory returns a new database object, and a function for cleaning it up.
type mutationLogsFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) keyserver.MutationLogs

// RunMutationLogsTests runs all the tests against the provided storage implementation.
func RunMutationLogsTests(t *testing.T, factory mutationLogsFactory) {
	ctx := context.Background()
	b := &mutationLogsTests{}
	for name, f := range map[string]func(ctx context.Context, t *testing.T, f mutationLogsFactory){
		// TODO(gbelvin): Discover test methods via reflection.
		"TestReadLog":      b.TestReadLog,
		"TestReadLogExact": b.TestReadLogExact,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

type mutationLogsTests struct{}

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(): %v", err)
	}
	return b
}

// TestReadLog ensures that reads happen in atomic units of batch size.
func (mutationLogsTests) TestReadLog(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestReadLog"
	logID := int64(5) // Any log ID.
	m := newForTest(ctx, t, directoryID, logID)

	type entryID struct {
		logID   int64
		wm      water.Mark
		localID int64
	}
	ids := make([]entryID, 0, 30)

	// Write ten batches.
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		batch := []*pb.EntryUpdate{entry, entry, entry}
		wm, err := m.SendBatch(ctx, directoryID, logID, batch)
		if err != nil {
			t.Fatalf("Send(): %v", err)
		}
		for local := 0; local < 3; local++ { // Save the 3 entries' IDs.
			ids = append(ids, entryID{logID: logID, wm: wm, localID: int64(local)})
		}
	}
	highWM := ids[len(ids)-1].wm.Add(1)

	for _, tc := range []struct {
		limit int32
		want  int
	}{
		{limit: 0, want: 0},
		{limit: 1, want: 3},    // We asked for 1 item, which gets us into the first batch, so we return 3 items.
		{limit: 3, want: 3},    // We asked for 3 items, which gets us through the first batch, so we return 3 items.
		{limit: 4, want: 6},    // Reading 4 items gets us into the second batch of size 3.
		{limit: 100, want: 30}, // Reading all the items gets us the 30 items we wrote.
	} {
		t.Run(fmt.Sprintf("%d", tc.limit), func(t *testing.T) {
			rows, err := m.ReadLog(ctx, directoryID, logID, water.Mark{}, highWM, tc.limit)
			if err != nil {
				t.Fatalf("ReadLog: %v", err)
			}
			if got := len(rows); got != tc.want {
				t.Fatalf("ReadLog: len: %v, want %v", got, tc.want)
			}
			gotIDs := make([]entryID, 0, len(rows))
			for _, row := range rows {
				gotIDs = append(gotIDs, entryID{logID: row.LogID, wm: row.ID, localID: row.LocalID})
			}
			if want := ids[:tc.want]; !reflect.DeepEqual(gotIDs, want) {
				t.Errorf("ReadLog: IDs mismatch: got %v, want %v", gotIDs, want)
			}
		})
	}
}

// TestReadLogExact ensures that reads respect the low inclusive, high exclusive API.
func (mutationLogsTests) TestReadLogExact(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestReadLogExact"
	logID := int64(5) // Any log ID.
	m := newForTest(ctx, t, directoryID, logID)
	// Write ten batches.
	idx := make([]water.Mark, 0, 10)
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte{i}}}
		ts, err := m.SendBatch(ctx, directoryID, logID, []*pb.EntryUpdate{entry})
		if err != nil {
			t.Fatalf("Send(): %v", err)
		}
		idx = append(idx, ts)
	}

	for i, tc := range []struct {
		low, high water.Mark
		want      []byte
	}{
		// {low: idx[0], high: idx[0], want: []byte{}}, // Not supported by Cloud Spanner
		{low: idx[0], high: idx[1], want: []byte{0}},
		{low: idx[0], high: idx[9], want: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{low: idx[1], high: idx[9], want: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		// Ensure that adding 1 correctly modifies the range semantics.
		{low: idx[0].Add(1), high: idx[9], want: []byte{1, 2, 3, 4, 5, 6, 7, 8}},
		{low: idx[0].Add(1), high: idx[9].Add(1), want: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			rows, err := m.ReadLog(ctx, directoryID, logID, tc.low, tc.high, 100)
			if err != nil {
				t.Fatalf("ReadLog(): %v", err)
			}
			got := make([]byte, 0, len(rows))
			for _, r := range rows {
				i := r.Mutation.Entry[0]
				got = append(got, i)
			}
			if !cmp.Equal(got, tc.want) {
				t.Fatalf("ReadLog(%v,%v): got %v, want %v", tc.low, tc.high, got, tc.want)
			}
		})
	}
}

func (mutationLogsTests) TestConcurrentWrites(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestConcurrentWrites"
	logID := int64(5)
	m := newForTest(ctx, t, directoryID, logID)
	for i, concurrency := range []int{1, 2, 4, 8, 16, 32, 64} {
		var g errgroup.Group
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{byte(i)}})}}
		high := water.Mark{}
		var highMu sync.Mutex
		for i := 0; i < concurrency; i++ {
			g.Go(func() error {
				wm, err := m.SendBatch(ctx, directoryID, logID, []*pb.EntryUpdate{entry})
				highMu.Lock()
				defer highMu.Unlock()
				if wm.Value() > high.Value() {
					high = wm
				}
				return err
			})
		}
		if err := g.Wait(); err != nil {
			t.Errorf("concurrency: %d, err: %v", concurrency, err)
		}
		rows, err := m.ReadLog(ctx, directoryID, logID, water.Mark{}, high, 100)
		if err != nil {
			t.Errorf("ReadLog: err: %v", err)
		}
		if got := len(rows); got != concurrency {
			t.Errorf("ReadLog() returned %d rows, want %v", got, concurrency)
		}
	}
}
