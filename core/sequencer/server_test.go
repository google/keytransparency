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

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
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

func TestReadMessages(t *testing.T) {
	ctx := context.Background()
	directoryID := "directoryID"
	s := Server{logs: fakeLogs{
		0: make([]mutator.LogMessage, 10),
		1: make([]mutator.LogMessage, 20),
	}}

	for _, tc := range []struct {
		meta      *spb.MapMetadata
		batchSize int32
		want      int
	}{
		{batchSize: 1, want: 9, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 0, LowestWatermark: 0, HighestWatermark: 9},
		}}},
		{batchSize: 1, want: 19, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 0, LowestWatermark: 0, HighestWatermark: 9},
			{LogId: 1, LowestWatermark: 0, HighestWatermark: 10},
		}}},
	} {
		msgs, err := s.readMessages(ctx, directoryID, tc.meta, tc.batchSize)
		if err != nil {
			t.Errorf("readMessages(): %v", err)
		}
		if got := len(msgs); got != tc.want {
			t.Errorf("readMessages(): len: %v, want %v", got, tc.want)
		}
	}
}

func TestHighWatermarks(t *testing.T) {
	ctx := context.Background()
	directoryID := "directoryID"
	s := Server{logs: fakeLogs{
		0: make([]mutator.LogMessage, 10),
		1: make([]mutator.LogMessage, 20),
	}}

	for _, tc := range []struct {
		desc      string
		batchSize int32
		count     int32
		last      spb.MapMetadata
		next      spb.MapMetadata
	}{
		{desc: "nobatch", batchSize: 30, count: 28,
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestWatermark: 9},
				{LogId: 1, HighestWatermark: 19}}}},
		{desc: "exactbatch", batchSize: 20, count: 20,
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestWatermark: 9},
				{LogId: 1, HighestWatermark: 11}}}},
		{desc: "batchwprev", batchSize: 20, count: 19,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestWatermark: 9}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, LowestWatermark: 9, HighestWatermark: 9},
				{LogId: 1, HighestWatermark: 19}}}},
		// Don't drop existing watermarks.
		{desc: "keep existing", batchSize: 1, count: 1,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 1, HighestWatermark: 9}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestWatermark: 1},
				{LogId: 1, LowestWatermark: 9, HighestWatermark: 9}}}},
		{desc: "logs that dont move", batchSize: 0, count: 0,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 3, HighestWatermark: 9}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0},
				{LogId: 1},
				{LogId: 3, LowestWatermark: 9, HighestWatermark: 9}}}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, next, err := s.HighWatermarks(ctx, directoryID, &tc.last, tc.batchSize)
			if err != nil {
				t.Fatalf("HighWatermarks(): %v", err)
			}
			if count != tc.count {
				t.Errorf("HighWatermarks(): count: %v, want %v", count, tc.count)
			}
			if !cmp.Equal(next, &tc.next) {
				t.Errorf("HighWatermarks(): diff(-got, +want): %v", cmp.Diff(next, &tc.next))
			}
		})
	}
}
