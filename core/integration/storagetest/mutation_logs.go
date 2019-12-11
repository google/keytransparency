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
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/keyserver"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// mutationLogsFactory returns a new database object, and a function for cleaning it up.
type mutationLogsFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) (keyserver.MutationLogs, func(context.Context))

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

// The minimum timestamp supported between all implementations.
var minWatermark = time.Unix(0, 0)

// TestReadLog ensures that reads happen in atomic units of batch size.
func (mutationLogsTests) TestReadLog(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestReadLog"
	logID := int64(5) // Any log ID.
	m, done := newForTest(ctx, t, directoryID, logID)
	defer done(ctx)
	// Write ten batches.
	var lastTS time.Time
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		ts, err := m.Send(ctx, directoryID, logID, entry, entry, entry)
		if err != nil {
			t.Fatalf("Send(): %v", err)
		}
		if ts.Before(minWatermark) {
			t.Fatalf("Send(): %v is before min watermark %v", ts, minWatermark)
		}
		lastTS = ts
	}

	for i, tc := range []struct {
		limit int32
		want  int
	}{
		{limit: 0, want: 0},
		{limit: 1, want: 3},    // We asked for 1 item, which gets us into the first batch, so we return 3 items.
		{limit: 3, want: 3},    // We asked for 3 items, which gets us through the first batch, so we return 3 items.
		{limit: 4, want: 6},    // Reading 4 items gets us into the second batch of size 3.
		{limit: 100, want: 30}, // Reading all the items gets us the 30 items we wrote.
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			rows, err := m.ReadLog(ctx, directoryID, logID, minWatermark, lastTS.Add(1), tc.limit)
			if err != nil {
				t.Fatalf("ReadLog(%v): %v", tc.limit, err)
			}
			if got := len(rows); got != tc.want {
				t.Fatalf("ReadLog(%v): len: %v, want %v", tc.limit, got, tc.want)
			}
		})
	}
}

// TestReadLogExact ensures that reads respect the low inclusive, high exclusive API.
func (mutationLogsTests) TestReadLogExact(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestReadLogExact"
	logID := int64(5) // Any log ID.
	m, done := newForTest(ctx, t, directoryID, logID)
	defer done(ctx)
	// Write ten batches.
	idx := make([]time.Time, 0, 10)
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte{i}}}
		ts, err := m.Send(ctx, directoryID, logID, entry)
		if err != nil {
			t.Fatalf("Send(): %v", err)
		}
		idx = append(idx, ts)
	}

	for i, tc := range []struct {
		low, high time.Time
		want      []byte
	}{
		{low: idx[0], high: idx[0], want: []byte{}},
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
