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
	"fmt"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/sequencer/mapper"
	"github.com/google/keytransparency/core/sequencer/runner"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const directoryID = "directoryID"

func fakeMetric(_ string) {}

type fakeLogs map[int64][]mutator.LogMessage

func (l fakeLogs) ReadLog(ctx context.Context, directoryID string, logID, low, high int64,
	batchSize int32) ([]*mutator.LogMessage, error) {
	refs := make([]*mutator.LogMessage, 0, int(high-low))
	for i := low; i < high; i++ {
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
	if high > int64(len(l[logID])) {
		high = int64(len(l[logID]))
	}
	count := int32(high - start)
	return count, high, nil
}

type fakeTrillianFactory struct {
	tmap trillianMap
	tlog trillianLog
}

func (t *fakeTrillianFactory) MapClient(_ context.Context, _ string) (trillianMap, error) {
	return t.tmap, nil
}

func (t *fakeTrillianFactory) LogClient(_ context.Context, _ string) (trillianLog, error) {
	return t.tlog, nil
}

type fakeMap struct {
	MapClient
	latestMapRoot *types.MapRootV1
}

func (m *fakeMap) GetAndVerifyLatestMapRoot(_ context.Context) (*tpb.SignedMapRoot, *types.MapRootV1, error) {
	return nil, m.latestMapRoot, nil
}

type fakeBatcher struct {
	highestRev int64
	batches    map[int64]*spb.MapMetadata
}

func (b *fakeBatcher) HighestRev(_ context.Context, _ string) (int64, error) {
	return b.highestRev, nil
}
func (b *fakeBatcher) WriteBatchSources(_ context.Context, _ string, rev int64, meta *spb.MapMetadata) error {
	b.batches[rev] = meta
	return nil
}
func (b *fakeBatcher) ReadBatch(_ context.Context, _ string, rev int64) (*spb.MapMetadata, error) {
	meta, ok := b.batches[rev]
	if !ok {
		return nil, fmt.Errorf("batch %v not found", rev)
	}
	return meta, nil
}

func TestDefineRevisions(t *testing.T) {
	// Verify that outstanding revisions prevent future revisions from being created.
	ctx := context.Background()
	mapRev := int64(2)
	initMetrics.Do(func() { createMetrics(monitoring.InertMetricFactory{}) })
	s := Server{
		logs: fakeLogs{
			0: make([]mutator.LogMessage, 10),
			1: make([]mutator.LogMessage, 20),
		},
		trillian: &fakeTrillianFactory{
			tmap: &fakeMap{latestMapRoot: &types.MapRootV1{Revision: uint64(mapRev)}},
		},
	}

	for _, tc := range []struct {
		desc       string
		highestRev int64
		want       []int64
	}{
		// Blocked: Highest Rev > latestMapRoot.Rev
		{desc: "blocked", highestRev: mapRev + 1, want: []int64{mapRev + 1}},
		{desc: "unblocked", highestRev: mapRev, want: []int64{mapRev + 1}},
		{desc: "lagging", highestRev: mapRev + 3, want: []int64{mapRev + 1, mapRev + 2, mapRev + 3}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			s.batcher = &fakeBatcher{highestRev: tc.highestRev, batches: make(map[int64]*spb.MapMetadata)}
			got, err := s.DefineRevisions(ctx, &spb.DefineRevisionsRequest{
				DirectoryId: directoryID,
				MinBatch:    1,
				MaxBatch:    10})
			if err != nil {
				t.Fatalf("DefineRevisions(): %v", err)
			}
			if !cmp.Equal(got.OutstandingRevisions, tc.want) {
				t.Errorf("DefineRevisions(): %v, want %v", got, tc.want)
			}
		})
	}

}

func TestReadMessages(t *testing.T) {
	ctx := context.Background()
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
			{LogId: 0, LowestInclusive: 1, HighestExclusive: 10},
		}}},
		{batchSize: 1, want: 19, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 0, LowestInclusive: 1, HighestExclusive: 10},
			{LogId: 1, LowestInclusive: 1, HighestExclusive: 11},
		}}},
	} {
		logSlices := runner.DoMapMetaFn(mapper.MapMetaFn, tc.meta, fakeMetric)
		logItems, err := runner.DoReadFn(ctx, s.readMessages, logSlices, directoryID, tc.batchSize, fakeMetric)
		if err != nil {
			t.Errorf("readMessages(): %v", err)
		}
		if got := len(logItems); got != tc.want {
			t.Errorf("readMessages(): len: %v, want %v", got, tc.want)
		}
	}
}

func TestHighWatermarks(t *testing.T) {
	ctx := context.Background()
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
		{desc: "nobatch", batchSize: 30, count: 30,
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestExclusive: 10},
				{LogId: 1, HighestExclusive: 20}}}},
		{desc: "exactbatch", batchSize: 20, count: 20,
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestExclusive: 10},
				{LogId: 1, HighestExclusive: 10}}}},
		{desc: "batchwprev", batchSize: 20, count: 20,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestExclusive: 10}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, LowestInclusive: 10, HighestExclusive: 10},
				{LogId: 1, HighestExclusive: 20}}}},
		// Don't drop existing watermarks.
		{desc: "keep existing", batchSize: 1, count: 1,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 1, HighestExclusive: 10}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0, HighestExclusive: 1},
				{LogId: 1, LowestInclusive: 10, HighestExclusive: 10}}}},
		{desc: "logs that dont move", batchSize: 0, count: 0,
			last: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 3, HighestExclusive: 10}}},
			next: spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				{LogId: 0},
				{LogId: 1},
				{LogId: 3, LowestInclusive: 10, HighestExclusive: 10}}}},
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
