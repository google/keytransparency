// Copyright 2016 Google Inc. All Rights Reserved.
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
package mutationstorage

import (
	"context"
	"database/sql"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/integration/storagetest"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	_ "github.com/mattn/go-sqlite3"
)

const directoryID = "default"

func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func TestBatchIntegration(t *testing.T) {
	storageFactory := func(context.Context, *testing.T) storagetest.Batcher {
		m, err := New(newDB(t))
		if err != nil {
			t.Fatalf("Failed to create mutations: %v", err)
		}
		return m
	}

	storagetest.RunBatchStorageTests(t, storageFactory)
}

func TestWriteBatch(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	domainID := "writebatchtest"
	for _, tc := range []struct {
		rev     int64
		wantErr bool
		sources []*spb.MapMetadata_SourceSlice
	}{
		// Tests are cumulative.
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 11}}},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 12}}, wantErr: true},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 21}}, wantErr: true},
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{}, wantErr: true},
		{rev: 1, sources: []*spb.MapMetadata_SourceSlice{}},
		{rev: 1, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 11}}, wantErr: true},
	} {
		err := m.WriteBatchSources(ctx, domainID, tc.rev, &spb.MapMetadata{Sources: tc.sources})
		if got, want := err != nil, tc.wantErr; got != want {
			t.Errorf("WriteBatchSources(%v, %v): err: %v. code: %v, want %v",
				tc.rev, tc.sources, err, got, want)
		}
	}
}

func TestReadBatch(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	domainID := "readbatchtest"
	for _, tc := range []struct {
		rev  int64
		want *spb.MapMetadata
	}{
		{rev: 0, want: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 1, HighestExclusive: 11},
			{LogId: 2, HighestExclusive: 21},
		}}},
		{rev: 1, want: &spb.MapMetadata{Sources: []*spb.MapMetadata_SourceSlice{
			{LogId: 1, HighestExclusive: 12},
			{LogId: 2, HighestExclusive: 23},
		}}},
	} {
		if err := m.WriteBatchSources(ctx, domainID, tc.rev, tc.want); err != nil {
			t.Fatalf("WriteBatch(%v): %v", tc.rev, err)
		}
		got, err := m.ReadBatch(ctx, domainID, tc.rev)
		if err != nil {
			t.Fatalf("ReadBatch(%v): %v", tc.rev, err)
		}
		if !cmp.Equal(got, tc.want, cmp.Comparer(proto.Equal)) {
			t.Errorf("ReadBatch(%v): %v, want %v", tc.rev, got, tc.want)
		}
	}
}

func TestHightestRev(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	domainID := "writebatchtest"
	for _, tc := range []struct {
		rev     int64
		sources []*spb.MapMetadata_SourceSlice
	}{
		// Tests are cumulative.
		{rev: 0, sources: []*spb.MapMetadata_SourceSlice{{LogId: 1, HighestExclusive: 11}}},
		{rev: 1, sources: []*spb.MapMetadata_SourceSlice{}},
	} {
		err := m.WriteBatchSources(ctx, domainID, tc.rev, &spb.MapMetadata{Sources: tc.sources})
		if err != nil {
			t.Errorf("WriteBatchSources(%v, %v): err: %v", tc.rev, tc.sources, err)
		}
		got, err := m.HighestRev(ctx, domainID)
		if err != nil {
			t.Errorf("HighestRev(): %v", err)
		}
		if got != tc.rev {
			t.Errorf("HighestRev(): %v, want %v", got, tc.rev)
		}
	}
}
