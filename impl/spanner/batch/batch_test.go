// Copyright 2020 Google Inc. All Rights Reserved.
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

package batch

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/spanner/directory"
	"github.com/google/keytransparency/impl/spanner/testutil"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dtype "github.com/google/keytransparency/core/directory"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	ktspanner "github.com/google/keytransparency/impl/spanner"
	tpb "github.com/google/trillian"
)

func NewForTest(ctx context.Context, t *testing.T, dirID string) (*Table, func()) {
	t.Helper()
	ddl, err := ktspanner.ReadDDL()
	if err != nil {
		t.Fatal(err)
	}
	client, cleanup := testutil.CreateDatabase(ctx, t, ddl)
	b := New(client)

	if err := directory.New(client).Write(ctx, &dtype.Directory{
		DirectoryID: dirID,
		Map:         &tpb.Tree{},
		Log:         &tpb.Tree{},
		VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
	}); err != nil {
		t.Fatalf("directories.Write(%v): %v", dirID, err)
	}

	return b, cleanup
}

func TestNewForTest(t *testing.T) {
	ctx := context.Background()
	directoryID := "new"
	_, done := NewForTest(ctx, t, directoryID)
	defer done()
}

func TestBatchIntegration(t *testing.T) {
	storageFactory :=
		func(ctx context.Context, t *testing.T, dirID string) (sequencer.Batcher, func(context.Context)) {
			b, done := NewForTest(ctx, t, dirID)
			return b, func(_ context.Context) { done() }
		}

	storagetest.RunBatchStorageTests(t, storageFactory)
}

func TestWriteBatch(t *testing.T) {
	ctx := context.Background()
	directoryID := "writebatch"
	m, done := NewForTest(ctx, t, directoryID)
	defer done()
	for _, tc := range []struct {
		rev     int64
		wantErr bool
		sources []*spb.MapMetadata_SourceSlice
	}{
		// Tests are cumulative.
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 10}}},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 11}}, wantErr: true},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 2, HighestExclusive: 20}}, wantErr: true},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{}, wantErr: true},
		{rev: 1, sources: []*spb.MapMetadata_SourceSlice{}},
		{rev: 1, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 10}}, wantErr: true},
	} {
		err := m.WriteBatchSources(ctx, directoryID, tc.rev, &spb.MapMetadata{Sources: tc.sources})
		if got, want := err != nil, tc.wantErr; got != want {
			t.Errorf("WriteBatchSources(%v, %v): err: %v. code: %v, want %v",
				tc.rev, tc.sources, err, got, want)
		}
	}
}

func TestReadBatch(t *testing.T) {
	ctx := context.Background()
	directoryID := "readbatch"
	m, done := NewForTest(ctx, t, directoryID)
	defer done()

	for _, tc := range []struct {
		rev  int64
		want *spb.MapMetadata
	}{
		{rev: 0, want: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 1, HighestExclusive: 10},
			{LogId: 2, HighestExclusive: 20},
		}}},
		{rev: 1, want: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 1, HighestExclusive: 11},
			{LogId: 2, HighestExclusive: 22},
		}}},
	} {
		if err := m.WriteBatchSources(ctx, directoryID, tc.rev, tc.want); err != nil {
			t.Fatalf("WriteBatch(%v): %v", tc.rev, err)
		}
		got, err := m.ReadBatch(ctx, directoryID, tc.rev)
		if err != nil {
			t.Fatalf("ReadBatch(%v): %v", tc.rev, err)
		}
		if !cmp.Equal(got, tc.want, cmp.Comparer(proto.Equal)) {
			t.Errorf("ReadBatch(%v): %v, want %v", tc.rev, got, tc.want)
		}
	}
	// Read batch that doesn't exist
	_, err := m.ReadBatch(ctx, directoryID, 2)
	if got, want := status.Code(err), codes.NotFound; got != want {
		t.Fatalf("ReadBatch(%v): %v", got, want)
	}
}

func TestHighestRev(t *testing.T) {
	ctx := context.Background()
	directoryID := "highestrev"
	m, done := NewForTest(ctx, t, directoryID)
	defer done()

	for _, tc := range []struct {
		desc    string
		rev     int64
		sources []*spb.MapMetadata_SourceSlice
	}{
		// Tests are cumulative.
		{desc: "rev0", rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 10}}},
		{desc: "rev1", rev: 1, sources: []*spb.MapMetadata_SourceSlice{}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			err := m.WriteBatchSources(ctx, directoryID, tc.rev, &spb.MapMetadata{Sources: tc.sources})
			if err != nil {
				t.Errorf("WriteBatchSources(%v, %v): err: %v", tc.rev, tc.sources, err)
			}
			got, err := m.HighestRev(ctx, directoryID)
			if err != nil {
				t.Errorf("HighestRev(): %v", err)
			}
			if got != tc.rev {
				t.Errorf("HighestRev(): %v, want %v", got, tc.rev)
			}
		})
	}
}
