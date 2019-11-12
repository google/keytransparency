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

	"github.com/google/go-cmp/cmp"
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
// nolint:gocyclo
func (mutationLogsReaderTests) TestHighWatermark(ctx context.Context, t *testing.T, newForTest logsRWFactory) {
	directoryID := "TestHighWatermark"
	logID := int64(1)
	m, done := newForTest(ctx, t, directoryID, logID)
	defer done(ctx)

	// Setup the test by writing 10 items to the mutation log and
	// collecting the reported high water mark after each write.
	sent := []time.Time{} // Timesttamps that Send reported.
	hwm := []time.Time{}  // High water marks collected after each Send.
	maxIndex := 9
	for i := 0; i <= maxIndex; i++ {
		ts, err := m.Send(ctx, directoryID, logID,
			&pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte{byte(i)}}})
		if err != nil {
			t.Fatalf("Send(%v): %v", logID, err)
		}
		count, wm, err := m.HighWatermark(ctx, directoryID, logID, minWatermark, 100 /*batchSize*/)
		if err != nil {
			t.Fatalf("HighWatermark(): %v", err)
		}
		if want := int32(i) + 1; count != want {
			t.Fatalf("HighWatermark(): count %v, want %v", count, want)
		}
		sent = append(sent, ts)
		hwm = append(hwm, wm)
	}

	arbitraryTime := time.Date(1, 2, 3, 4, 5, 6, 7, time.UTC)
	// Tests that query HighWatermarks with varying parameters and validate results directly.
	for _, tc := range []struct {
		desc  string
		start time.Time
		batch int32
		want  time.Time
	}{
		// Verify that high watermarks preserves the starting time when batch size is 0.
		{desc: "preserve start batch 0", start: arbitraryTime, batch: 0, want: arbitraryTime},
		// Verify that high watermarks preserves the starting time when there are no rows in the result.
		{desc: "preserve start rows 0", start: sent[maxIndex].Add(time.Second), batch: 1, want: sent[maxIndex].Add(time.Second)},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, got, err := m.HighWatermark(ctx, directoryID, logID, tc.start, tc.batch)
			if err != nil {
				t.Errorf("HighWatermark(): %v", err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("HighWatermark(%v, %v) high: %v, want %v", tc.start, tc.batch, got, tc.want)
			}
			if count != 0 {
				t.Errorf("HighWatermark(): count %v, want 0", count)
			}
		})
	}

	// Tests that use the watermarks defined during setup.
	for _, tc := range []struct {
		desc     string
		readHigh time.Time
		want     []byte
	}{
		// Verify that highwatermark can retrieve all the data written so far.
		{desc: "all", readHigh: hwm[maxIndex], want: []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
		// Verify that data retrieved at highwatermark doesn't change when more data is written.
		{desc: "stable", readHigh: hwm[2], want: []byte{0, 1, 2}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			low := minWatermark
			rows, err := m.ReadLog(ctx, directoryID, logID, low, tc.readHigh, 100)
			if err != nil {
				t.Fatalf("ReadLog(): %v", err)
			}
			got := make([]byte, 0, len(rows))
			for _, r := range rows {
				i := r.Mutation.Entry[0]
				got = append(got, i)
			}
			if !cmp.Equal(got, tc.want) {
				t.Fatalf("ReadLog(%v,%v): got %v, want %v", low, tc.readHigh, got, tc.want)
			}
		})
	}

	// Tests that query HighWatermarks with varying parameters and validate results using ReadLog.
	for _, tc := range []struct {
		desc  string
		start time.Time
		batch int32
		want  []byte
	}{
		// Verify that limiting batch size controls the number of items returned.
		{desc: "limit batch", start: sent[0], batch: 2, want: []byte{0, 1}},
		// Verify that advancing start by 1 with the same batch size advances the results by one.
		{desc: "start 1", start: sent[1], batch: 2, want: []byte{1, 2}},
		// Verify that watermarks in between primary keys resolve correctly.
		{desc: "start 0.1", start: sent[0].Add(1), batch: 2, want: []byte{1, 2}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, wm, err := m.HighWatermark(ctx, directoryID, logID, tc.start, tc.batch)
			if err != nil {
				t.Errorf("HighWatermark(): %v", err)
			}
			if want := int32(len(tc.want)); count != want {
				t.Errorf("HighWatermark() count: %v, want %v", count, want)
			}

			rows, err := m.ReadLog(ctx, directoryID, logID, tc.start, wm, tc.batch)
			if err != nil {
				t.Fatalf("ReadLog(): %v", err)
			}
			got := make([]byte, 0, len(rows))
			for _, r := range rows {
				i := r.Mutation.Entry[0]
				got = append(got, i)
			}
			if !cmp.Equal(got, tc.want) {
				t.Fatalf("ReadLog(%v,%v): got %v, want %v", tc.start, wm, got, tc.want)
			}
		})
	}
}
