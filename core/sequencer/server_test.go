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
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

type fakeLogs map[int64][]mutator.LogMessage

func (l fakeLogs) ReadLog(ctx context.Context, domainID string, logID, low, high int64, batchSize int32) ([]*mutator.LogMessage, error) {
	refs := make([]*mutator.LogMessage, 0, int(high-low))
	for i := low + 1; i < high+1; i++ {
		l[logID][i].ID = i
		refs = append(refs, &l[logID][i])
	}
	return refs, nil

}

func (l fakeLogs) ListLogs(ctx context.Context, domainID string, writable bool) ([]int64, error) {
	logIDs := make([]int64, 0, len(l))
	for logID := range l {
		logIDs = append(logIDs, logID)
	}
	// sort logsIDs for test repeatability.
	sort.Slice(logIDs, func(i, j int) bool { return logIDs[i] < logIDs[j] })
	return logIDs, nil
}

func (l fakeLogs) HighWatermark(ctx context.Context, domainID string, logID, start int64, batchSize int32) (int32, int64, error) {
	high := start + int64(batchSize)
	if high > int64(len(l[logID]))-1 {
		high = int64(len(l[logID])) - 1
	}
	count := int32(high - start)
	return count, high, nil

}

func TestReadMessages(t *testing.T) {
	ctx := context.Background()
	domainID := "domainID"
	s := Server{logs: fakeLogs{
		0: make([]mutator.LogMessage, 10),
		1: make([]mutator.LogMessage, 20),
	}}

	for _, tc := range []struct {
		sources   SourcesEntry
		batchSize int32
		want      int
	}{
		{batchSize: 1, want: 9, sources: SourcesEntry{0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9}}},
		{batchSize: 1, want: 19, sources: SourcesEntry{
			0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9},
			1: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 10}}},
	} {
		msgs, err := s.readMessages(ctx, domainID, tc.sources, tc.batchSize)
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
	domainID := "domainID"
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
		{batchSize: 1, starts: Watermarks{1: 9}, count: 1, highs: Watermarks{0: 1, 1: 9}},       // Don't drop existing watermarks.
		{batchSize: 0, starts: Watermarks{3: 9}, count: 0, highs: Watermarks{0: 0, 1: 0, 3: 9}}, // Don't drop pre-existing watermarks.
	} {
		count, highs, err := s.HighWatermarks(ctx, domainID, tc.starts, tc.batchSize)
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

func logMsg(t *testing.T, id int64, signer *tink.KeysetHandle) *ktpb.EntryUpdate {
	t.Helper()
	index := []byte{byte(id)}
	userID := string(id)
	m := entry.NewMutation(index, "domain", "app", userID)
	signers := []*tink.KeysetHandle{signer}
	pubkey, err := signer.Public()
	if err != nil {
		t.Fatalf("Public(): %v", err)
	}
	if err := m.ReplaceAuthorizedKeys(pubkey.Keyset()); err != nil {
		t.Fatalf("ReplaceAuthorizedKeys(): %v", err)
	}
	update, err := m.SerializeAndSign(signers, 0)
	if err != nil {
		t.Fatalf("SerializeAndSign(): %v", err)
	}

	return &ktpb.EntryUpdate{
		Mutation:  update.EntryUpdate.Mutation,
		Committed: &ktpb.Committed{},
	}
}

// TestDuplicateMutations verifies that each call to tlog.SetLeaves specifies
// each mapleaf.Index at most ONCE.
func TestDuplicateMutations(t *testing.T) {

	keyset1, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.NewKeysetHandle(): %v", err)
	}
	keyset2, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.NewKeysetHandle(): %v", err)
	}
	s := &Server{}

	for _, tc := range []struct {
		desc       string
		msgs       []*ktpb.EntryUpdate
		leaves     []*tpb.MapLeaf
		wantLeaves int
	}{
		{
			desc: "duplicate index, same data",
			msgs: []*ktpb.EntryUpdate{
				logMsg(t, 1, keyset1),
				logMsg(t, 1, keyset1),
			},
			wantLeaves: 1,
		},
		{
			desc: "duplicate index, different data",
			msgs: []*ktpb.EntryUpdate{
				logMsg(t, 2, keyset1),
				logMsg(t, 2, keyset2),
			},
			wantLeaves: 1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			domainID := "test"
			newLeaves, err := s.applyMutations(domainID, entry.New(), tc.msgs, tc.leaves)
			if err != nil {
				t.Errorf("applyMutations(): %v", err)
			}
			// Count unique map leaves.
			counts := make(map[string]int)
			for _, l := range newLeaves {
				counts[string(l.Index)]++
				if c := counts[string(l.Index)]; c > 1 {
					t.Errorf("Map leaf %x found %v times", l.Index, c)
				}
			}
			// Verify totals.
			if got, want := len(newLeaves), tc.wantLeaves; got != want {
				t.Errorf("applyMutations(): len: %v, want %v", got, want)
			}
		})
	}
}
