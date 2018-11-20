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

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/testutil"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

var signers = testutil.SignKeysetsFromPEMs(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBoLpoKGPbrFbEzF/ZktBSuGP+Llmx2wVKSkbdAdQ+3JoAoGCCqGSM49
AwEHoUQDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4hnGbXDPbdFlL1nmayhnqyEfR
dXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END EC PRIVATE KEY-----`)
var authKeys = testutil.VerifyKeysetFromPEMs(`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4
hnGbXDPbdFlL1nmayhnqyEfRdXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END PUBLIC KEY-----`).Keyset()

func makeEntry(t *testing.T, index, userID, data string) *ktpb.EntryUpdate {
	t.Helper()
	m := entry.NewMutation([]byte(index), "", userID)
	m.SetCommitment([]byte(data))
	m.ReplaceAuthorizedKeys(authKeys)
	update, err := m.SerializeAndSign(signers)
	if err != nil {
		t.Errorf("SerializeAndSign(): %v", err)
	}
	return update.EntryUpdate

}

func TestBeamEquivilance(t *testing.T) {
	ctx := context.Background()
	in := &spb.CreateRevisionRequest{
		DirectoryId: "test",
		Revision:    1,
	}
	mr := &emptyMap{}
	lr := fakeLog{1: {
		&ktpb.EntryUpdate{},
		makeEntry(t, "1", "alice", "alpha"),
		makeEntry(t, "2", "bob", "beta"),
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
		t.Run(tc.desc, func(t *testing.T) {
			mw1 := &mapWrites{}
			if err := createRevisionWithBeam(ctx, in, tc.meta, mw1, mr, lr); err != nil {
				t.Errorf("createRevisionWithBeam(): %v", err)
			}
			mw2 := &mapWrites{}
			if err := createRevisionWithChannels(ctx, in, tc.meta, mw2, mr, lr); err != nil {
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
	ints := beam.ParDo(s, func(i []byte, e func(int)) error {
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
		{in: []*tpb.MapLeaf{&tpb.MapLeaf{LeafValue: []byte("123")}}},
		{in: []*tpb.MapLeaf{
			&tpb.MapLeaf{LeafValue: []byte("abc")},
			&tpb.MapLeaf{LeafValue: []byte("def")},
		}},
	} {

		p := beam.NewPipeline()
		s := p.Root()

		// Split inputs and then recombine them.
		leaves := beam.ParDo(s, func(in []*tpb.MapLeaf, emit func(*tpb.MapLeaf)) {
			for _, l := range tc.in {
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
