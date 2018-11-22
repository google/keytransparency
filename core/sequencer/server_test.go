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

package sequencer

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/mutator"
)

type fakeLogs map[int64][]mutator.LogMessage

func (l fakeLogs) ReadLog(ctx context.Context, directoryID string, logID, low, high int64,
	batchSize int32) ([]*mutator.LogMessage, error) {
	refs := make([]*mutator.LogMessage, 0, int(high-low))
	for i := low + 1; i < high+1; i++ {
		l[logID][i].ID = i
		refs = append(refs, &l[logID][i])
	}
	return refs, nil

}

func (l fakeLogs) ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error) {
	logIDs := make([]int64, 0, len(l))
	for logID := range l {
		logIDs = append(logIDs, logID)
	}
	// sort logsIDs for test repeatability.
	sort.Slice(logIDs, func(i, j int) bool { return logIDs[i] < logIDs[j] })
	return logIDs, nil
}

func (l fakeLogs) HighWatermark(ctx context.Context, directoryID string, logID, start int64,
	batchSize int32) (int32, int64, error) {
	high := start + int64(batchSize)
	if high > int64(len(l[logID]))-1 {
		high = int64(len(l[logID])) - 1
	}
	count := int32(high - start)
	return count, high, nil
}

func TestHighWatermarks(t *testing.T) {
	ctx := context.Background()
	directoryID := "directoryID"
	s := Server{logs: fakeLogs{
		0: make([]mutator.LogMessage, 10),
		1: make([]mutator.LogMessage, 20),
	}}

	for _, tc := range []struct {
		starts    Watermarks
		batchSize int32
		count     int32
		highs     Watermarks
	}{
		{batchSize: 30, starts: Watermarks{}, count: 28, highs: Watermarks{0: 9, 1: 19}},
		{batchSize: 20, starts: Watermarks{}, count: 20, highs: Watermarks{0: 9, 1: 11}},
		{batchSize: 20, starts: Watermarks{0: 9}, count: 19, highs: Watermarks{0: 9, 1: 19}},
		// Don't drop existing watermarks.
		{batchSize: 1, starts: Watermarks{1: 9}, count: 1, highs: Watermarks{0: 1, 1: 9}},
		// Don't drop pre-existing watermarks.
		{batchSize: 0, starts: Watermarks{3: 9}, count: 0, highs: Watermarks{0: 0, 1: 0, 3: 9}},
	} {
		count, highs, err := s.HighWatermarks(ctx, directoryID, tc.starts, tc.batchSize)
		if err != nil {
			t.Errorf("HighWatermarks(): %v", err)
		}
		if count != tc.count {
			t.Errorf("HighWatermarks(): count: %v, want %v", count, tc.count)
		}
		if !cmp.Equal(highs, tc.highs) {
			t.Errorf("HighWatermarks(): %v, want %v", highs, tc.highs)
		}
	}
}
