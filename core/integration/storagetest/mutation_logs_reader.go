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
	"testing"
	"time"

	"github.com/google/keytransparency/core/sequencer"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// LogsReadWriter supports test's ability to write to and read from the mutation logs.
type LogsReadWriter interface {
	sequencer.LogsReader
	// Send submits the whole group of mutations atomically to a log.
	// TODO(gbelvin): Create a batch level object to make it clear that this a batch of updates.
	// Returns the timestamp that the mutation batch got written at.
	Send(ctx context.Context, directoryID string, logID int64, mutation ...*pb.EntryUpdate) (time.Time, error)
}

// logsRWFactory returns a new database object, and a function for cleaning it up.
type logsRWFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) (LogsReadWriter, func(context.Context))

// RunMutationLogsReaderTests runs all the tests against the provided storage implementation.
func RunMutationLogsReaderTests(t *testing.T, factory logsRWFactory) {
	ctx := context.Background()
	b := &mutationLogsReaderTests{}
	type TestFunc func(ctx context.Context, t *testing.T, f logsRWFactory)
	for name, f := range map[string]TestFunc{
		// TODO(gbelvin): Discover test methods via reflection.
		"TestHighWatermark": b.TestHighWatermark,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

type mutationLogsReaderTests struct{}

// TestHighWatermark ensures that reads respect the low inclusive, high exclusive API.
func (mutationLogsReaderTests) TestHighWatermark(ctx context.Context, t *testing.T, newForTest logsRWFactory) {
	directoryID := "TestHighWatermark"
	logIDs := []int64{1, 2}
	m, done := newForTest(ctx, t, directoryID, logIDs...)
	defer done(ctx)
	update := &pb.EntryUpdate{}

	idx := []time.Time{}
	for i := 0; i < 10; i++ {
		logID := int64(1)
		ts, err := m.Send(ctx, directoryID, logID, update)
		if err != nil {
			t.Fatalf("m.Send(%v): %v", logID, err)
		}
		idx = append(idx, ts)
	}

	for _, tc := range []struct {
		desc      string
		logID     int64
		start     time.Time
		batchSize int32
		count     int32
		want      time.Time
	}{
		{desc: "log1 max", logID: 1, batchSize: 100, start: idx[0], want: idx[9].Add(1), count: 10},
		{desc: "log2 empty", logID: 2, batchSize: 100, start: idx[0], want: idx[0]},
		{desc: "batch0", logID: 1, batchSize: 0, start: minWatermark, want: minWatermark},
		{desc: "batch0start55", logID: 1, start: minWatermark.Add(55 * time.Microsecond), batchSize: 0, want: minWatermark.Add(55 * time.Microsecond)},
		{desc: "batch5", logID: 1, start: idx[0], batchSize: 5, want: idx[4].Add(1), count: 5},
		{desc: "start1", logID: 1, start: idx[2], batchSize: 5, want: idx[6].Add(1), count: 5},
		{desc: "start8", logID: 1, start: idx[8], batchSize: 5, want: idx[9].Add(1), count: 2},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, got, err := m.HighWatermark(ctx, directoryID, tc.logID, tc.start, tc.batchSize)
			if err != nil {
				t.Errorf("highWatermark(): %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("highWatermark(%v) high: %v, want %v", tc.start, got, tc.want)
			}
			if count != tc.count {
				t.Errorf("highWatermark(%v) count: %v, want %v", tc.start, count, tc.count)
			}
		})
	}
}
