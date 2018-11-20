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

// +build !nobeam

package sequencer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/transforms/stats"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"
	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"

	"github.com/google/keytransparency/core/mutator"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

func TestBeamEquivilance(t *testing.T) {
	keyset1, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.NewKeysetHandle(): %v", err)
	}

	ctx := context.Background()
	in := &spb.CreateRevisionRequest{
		DirectoryId: "test",
		Revision:    1,
	}
	mr := &emptyMap{}
	lr := fakeLog{1: {
		&ktpb.EntryUpdate{},
		logMsg(t, 1, keyset1),
		logMsg(t, 2, keyset1),
	}}

	for _, tc := range []struct {
		desc string
		meta *spb.MapMetadata
	}{
		{desc: "empty", meta: &spb.MapMetadata{}},
		{desc: "one", meta: &spb.MapMetadata{
			Sources: map[int64]*spb.MapMetadata_SourceSlice{
				1: {HighestWatermark: 1},
			},
		}},
		{desc: "two", meta: &spb.MapMetadata{
			Sources: map[int64]*spb.MapMetadata_SourceSlice{
				1: {HighestWatermark: 2},
			},
		}},
	} {
		tc := tc
		t.Run(tc.desc, func(t *testing.T) {
			mw1 := &mapWrites{}
			if err := CreateRevisionWithBeam(ctx, in.DirectoryId, in.Revision,
				tc.meta, 1000, mw1, mr, lr); err != nil {
				t.Errorf("createRevisionWithBeam(): %v", err)
			}
			mw2 := &mapWrites{}
			if err := CreateRevisionWithChannels(ctx, in.DirectoryId, in.Revision,
				tc.meta, 1000, mw2, mr, lr); err != nil {
				t.Errorf("createRevisionWithChannels(): %v", err)
			}
			if !mw2.Called {
				t.Fatalf("MapWriter2 not called")

			}
			if !cmp.Equal(mw1.Leaves, mw2.Leaves,
				cmp.Comparer(proto.Equal),
				cmpopts.SortSlices(func(a, b *tpb.MapLeaf) bool {
					return bytes.Compare(a.LeafValue, b.LeafValue) < 0
				}),
			) {
				t.Errorf("results differ. beam: %v != channel: %v", mw1.Leaves, mw2.Leaves)
			}
		})
	}
}

type mapWrites struct {
	Leaves []*tpb.MapLeaf
	Called bool
}

func (m *mapWrites) WriteMap(ctx context.Context, leaves []*tpb.MapLeaf, meta *spb.MapMetadata, directoryID string) error {
	m.Leaves = leaves
	m.Called = true
	return nil
}

type emptyMap struct{}

func (m *emptyMap) ReadMap(ctx context.Context, indexes [][]byte, directoryID string,
	emit func(index []byte, leaf *tpb.MapLeaf)) error {
	for _, i := range indexes {
		emit(i, &tpb.MapLeaf{
			Index: i,
		})
	}
	return nil
}

type fakeLog map[int64][]*ktpb.EntryUpdate

func (l fakeLog) ReadLog(ctx context.Context, logID int64, s *spb.MapMetadata_SourceSlice,
	directoryID string, batchSize int32, emit func(*ktpb.EntryUpdate)) error {
	for _, e := range l[logID][s.LowestWatermark+1 : s.HighestWatermark+1] {
		emit(e)
	}
	return nil
}

func TestDontPanic(t *testing.T) {
	ctx := context.Background()
	p := beam.NewPipeline()
	s := p.Root()

	errDontPanic := errors.New("don't panic")
	ints := beam.ParDo(s, func(_ []byte, _ func(int)) error {
		return errDontPanic
	}, beam.Impulse(s))
	beam.ParDo0(s, func(i int) {}, ints)

	// Verify that e is returned through beamx.Run
	if err := beamx.Run(ctx, p); err != errDontPanic {
		t.Fatalf("beamx.Run(): %v", err)
	}
}

func TestEmptyRevision(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		in []*tpb.MapLeaf
	}{
		{in: []*tpb.MapLeaf{}},
		{in: []*tpb.MapLeaf{{LeafValue: []byte("123")}}},
		{in: []*tpb.MapLeaf{
			{LeafValue: []byte("abc")},
			{LeafValue: []byte("def")},
		}},
	} {
		tc := tc
		p := beam.NewPipeline()
		s := p.Root()

		// Split inputs and then recombine them.
		leaves := beam.ParDo(s, func(in []*tpb.MapLeaf, emit func(*tpb.MapLeaf)) {
			for _, l := range in {
				emit(l)
			}
		}, beam.Create(s, tc.in))
		ranOutput := false
		beam.ParDo0(s, func(got []*tpb.MapLeaf) error {
			if !cmp.Equal(got, tc.in,
				cmp.Comparer(proto.Equal),
				cmpopts.SortSlices(func(a, b *tpb.MapLeaf) bool { return bytes.Compare(a.LeafValue, b.LeafValue) < 0 })) {
				return fmt.Errorf("collectMapLeaves(): %v, want %v", got, tc.in)
			}
			ranOutput = true
			return nil
		}, collectMapLeaves(s, leaves))

		if err := beamx.Run(ctx, p); err != nil {
			t.Fatalf("beamx.Run(): %v", err)
		}
		if !ranOutput {
			t.Errorf("ranOutput: %v, want true", ranOutput)
		}
	}
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
		{batchSize: 1, want: 9, meta: &spb.MapMetadata{Sources: SourcesEntry{
			0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9},
		}}},
		{batchSize: 1, want: 19, meta: &spb.MapMetadata{Sources: SourcesEntry{
			0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9},
			1: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 10},
		}}},
	} {
		tc := tc
		p := beam.NewPipeline()
		scope := p.Root()

		meta := beam.Create(scope, tc.meta)
		// Read each logID in parallel.
		sourceSlices := beam.ParDo(scope, splitMeta, meta) // KV<logID, source>
		logItems := beam.ParDo(scope, s.ReadLog, sourceSlices,
			beam.SideInput{Input: beam.Create(scope, directoryID)},
			beam.SideInput{Input: beam.Create(scope, tc.batchSize)})
		count := stats.Sum(scope, beam.DropKey(scope, stats.Count(scope, logItems)))
		beam.ParDo0(scope, func(got int) error {
			if got != tc.want {
				return fmt.Errorf("readMessages(): len: %v, want %v", got, tc.want)
			}
			return nil
		}, count)

		if err := beamx.Run(ctx, p); err != nil {
			t.Errorf("beamx.Run(): %v", err)
		}

	}
}
