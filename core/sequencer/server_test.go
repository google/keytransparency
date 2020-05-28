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
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/sequencer/mapper"
	"github.com/google/keytransparency/core/sequencer/metadata"
	"github.com/google/keytransparency/core/sequencer/runner"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/impl/memory"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const directoryID = "directoryID"

var zero = water.Mark{}

func fakeMetric(_ string) {}

func init() {
	initMetrics.Do(func() { createMetrics(monitoring.InertMetricFactory{}) })
}

type fakeTrillianFactory struct {
	tmap   trillianMap
	tlog   trillianLog
	twrite *MapWriteClient
}

func (t *fakeTrillianFactory) MapClient(_ context.Context, _ string) (trillianMap, error) {
	return t.tmap, nil
}
func (t *fakeTrillianFactory) MapWriteClient(_ context.Context, _ string) (*MapWriteClient, error) {
	return t.twrite, nil
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

type fakeWrite struct{}

func (m *fakeWrite) GetLeavesByRevision(ctx context.Context, in *tpb.GetMapLeavesByRevisionRequest, opts ...grpc.CallOption) (*tpb.MapLeaves, error) {
	return nil, nil
}
func (m *fakeWrite) WriteLeaves(ctx context.Context, in *tpb.WriteMapLeavesRequest, opts ...grpc.CallOption) (*tpb.WriteMapLeavesResponse, error) {
	return nil, nil
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

func setupLogs(ctx context.Context, t *testing.T, dirID string, logLengths map[int64]int) (memory.MutationLogs, map[int64][]water.Mark) {
	t.Helper()
	fakeLogs := memory.NewMutationLogs()
	idx := make(map[int64][]water.Mark)
	for logID, msgs := range logLengths {
		if err := fakeLogs.AddLogs(ctx, dirID, logID); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < msgs; i++ {
			wm, err := fakeLogs.SendBatch(ctx, dirID, logID, []*pb.EntryUpdate{{}})
			if err != nil {
				t.Fatal(err)
			}
			idx[logID] = append(idx[logID], wm)
		}
	}
	return fakeLogs, idx
}

func newSource(logID int64, low, high water.Mark) *spb.MapMetadata_SourceSlice {
	return metadata.New(logID, low, high).Proto()
}

func TestDefiningRevisions(t *testing.T) {
	// Verify that outstanding revisions prevent future revisions from being created.
	ctx := context.Background()
	mapRev := int64(2)
	dirID := "foobar"
	fakeLogs, idx := setupLogs(ctx, t, dirID, map[int64]int{0: 10, 1: 20})
	s := Server{
		logs: fakeLogs,
		trillian: &fakeTrillianFactory{
			tmap: &fakeMap{latestMapRoot: &types.MapRootV1{Revision: uint64(mapRev)}},
		},
	}

	for _, tc := range []struct {
		desc       string
		highestRev int64
		meta       *spb.MapMetadata
		maxGap     int32
		wantNew    int64
	}{
		{desc: "alomost-blocked", highestRev: mapRev + 1, maxGap: 1, wantNew: mapRev + 2},
		{desc: "blocked", highestRev: mapRev + 2, wantNew: mapRev + 2},
		{desc: "unblocked", highestRev: mapRev, wantNew: mapRev + 1},
		{desc: "lagging", highestRev: mapRev + 3, wantNew: mapRev + 3},
		{desc: "skewed", highestRev: mapRev - 1, wantNew: mapRev - 1},
		{desc: "almost_drained", highestRev: mapRev,
			meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, water.NewMark(9)),
				newSource(1, zero, water.NewMark(20)),
			}},
			wantNew: mapRev + 1},
		{desc: "drained", highestRev: mapRev,
			meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, idx[0][9].Add(1)),
				newSource(1, zero, idx[1][19].Add(1)),
			}},
			wantNew: mapRev},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			s.batcher = &fakeBatcher{highestRev: tc.highestRev, batches: make(map[int64]*spb.MapMetadata)}
			s.batcher.WriteBatchSources(ctx, directoryID, tc.highestRev, tc.meta)

			gdrResp, err := s.GetDefinedRevisions(ctx,
				&spb.GetDefinedRevisionsRequest{DirectoryId: directoryID})
			if err != nil {
				t.Fatalf("GetDefinedRevisions(): %v", err)
			}
			gdrWant := &spb.GetDefinedRevisionsResponse{
				HighestApplied: mapRev,
				HighestDefined: tc.highestRev,
			}
			if got, want := gdrResp, gdrWant; !proto.Equal(got, want) {
				t.Errorf("GetDefinedRevisions(): %v, want %v", got, want)
			}

			drResp, err := s.DefineRevisions(ctx, &spb.DefineRevisionsRequest{
				DirectoryId:  directoryID,
				MinBatch:     1,
				MaxBatch:     10,
				MaxUnapplied: tc.maxGap})
			if err != nil {
				t.Fatalf("DefineRevisions(): %v", err)
			}
			drWant := &spb.DefineRevisionsResponse{
				HighestApplied: mapRev,
				HighestDefined: tc.wantNew,
			}
			if got, want := drResp, drWant; !proto.Equal(got, want) {
				t.Errorf("DefineRevisions(): %v, want %v", got, want)
			}
		})
	}
}

func TestReadMessages(t *testing.T) {
	ctx := context.Background()
	dirID := "TestReadMessages"
	fakeLogs, idx := setupLogs(ctx, t, dirID, map[int64]int{0: 10, 1: 20})
	s := Server{logs: fakeLogs}

	for _, tc := range []struct {
		meta      *spb.MapMetadata
		batchSize int32
		want      int
	}{
		{batchSize: 1, want: 9, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			newSource(0, idx[0][1], idx[0][9].Add(1)),
		}}},
		{batchSize: 10000, want: 9, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			newSource(0, idx[0][1], idx[0][9].Add(1)),
		}}},
		{batchSize: 1, want: 19, meta: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			newSource(0, idx[0][1], idx[0][9].Add(1)),
			newSource(1, idx[1][1], idx[1][10].Add(1)),
		}}},
	} {
		logSlices := runner.DoMapMetaFn(mapper.MapMetaFn, tc.meta, fakeMetric)
		logItems, err := runner.DoReadFn(ctx, s.readMessages, logSlices, directoryID, tc.batchSize, fakeMetric)
		if err != nil {
			t.Errorf("readMessages(): %v", err)
		}
		if got := len(logItems); got != tc.want {
			t.Errorf("readMessages(%v): len: %v, want %v", tc.meta, got, tc.want)
		}
	}
}

func TestHighWatermarks(t *testing.T) {
	ctx := context.Background()
	dirID := "TestHighWatermark"
	fakeLogs, idx := setupLogs(ctx, t, dirID, map[int64]int{0: 10, 1: 20})
	s := Server{logs: fakeLogs}

	for _, tc := range []struct {
		desc      string
		batchSize int32
		count     int32
		last      *spb.MapMetadata
		next      *spb.MapMetadata
	}{
		{desc: "nobatch", batchSize: 30, count: 30,
			next: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, idx[0][9].Add(1)),
				newSource(1, zero, idx[1][19].Add(1)),
			}}},
		{desc: "exactbatch", batchSize: 20, count: 20,
			next: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, idx[0][9].Add(1)),
				newSource(1, zero, idx[1][9].Add(1)),
			}}},
		{desc: "batchwprev", batchSize: 20, count: 20,
			last: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, idx[0][9].Add(2)),
			}},
			next: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				// Nothing to read from log 1, preserve watermark of log 1.
				newSource(0, idx[0][9].Add(2), idx[0][9].Add(2)),
				newSource(1, zero, idx[1][19].Add(1)),
			}}},
		// Don't drop existing watermarks.
		{desc: "keep existing", batchSize: 1, count: 1,
			last: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(1, zero, water.NewMark(10)),
			}},
			next: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, idx[0][0].Add(1)),
				// No reads from log 1, but don't drop the watermark.
				newSource(1, water.NewMark(10), water.NewMark(10)),
			}}},
		{desc: "logs that dont move", batchSize: 0, count: 0,
			last: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(3, zero, water.NewMark(10)),
			}},
			next: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
				newSource(0, zero, zero),
				newSource(1, zero, zero),
				newSource(3, water.NewMark(10), water.NewMark(10)),
			}}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			count, next, err := s.HighWatermarks(ctx, directoryID, tc.last, tc.batchSize)
			if err != nil {
				t.Fatalf("HighWatermarks(): %v", err)
			}
			if count != tc.count {
				t.Errorf("HighWatermarks(): count: %v, want %v", count, tc.count)
			}
			if !proto.Equal(next, tc.next) {
				t.Errorf("HighWatermarks(): diff(-got, +want): %v", cmp.Diff(next, tc.next))
			}
		})
	}
}
