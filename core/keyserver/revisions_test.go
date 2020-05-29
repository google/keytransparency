// Copyright 2017 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/sequencer/metadata"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/impl/memory"
	"github.com/google/trillian/testonly/matchers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	rtpb "github.com/google/keytransparency/core/keyserver/readtoken_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const directoryID = "directory"

func genInclusions(start, end int64) []*tpb.MapLeafInclusion {
	ret := make([]*tpb.MapLeafInclusion, end-start)
	for i := range ret {
		ret[i] = &tpb.MapLeafInclusion{}
	}
	return ret
}

// genIndexes produces indexes between [start+1 and end].
func genIndexes(start, end int64) [][]byte {
	indexes := make([][]byte, 0, end-start)
	for i := start; i < end; i++ {
		indexes = append(indexes, []byte(fmt.Sprintf("key_%v", i)))
	}
	return indexes
}

func genEntryUpdates(t *testing.T, start, end int64) []*pb.EntryUpdate {
	t.Helper()
	entries := make([]*pb.EntryUpdate, 0)
	for i := start; i < end; i++ {
		entries = append(entries, &pb.EntryUpdate{
			Mutation: &pb.SignedEntry{
				Entry: mustMarshal(t, &pb.Entry{
					Index: []byte(fmt.Sprintf("key_%v", i)),
				}),
			},
		})
	}
	return entries
}

func TestGetRevisionStream(t *testing.T) {
	srv := &Server{}
	err := srv.GetRevisionStream(nil, nil)
	if got, want := status.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}

func newSource(logID int64, low, high water.Mark) *spb.MapMetadata_SourceSlice {
	return metadata.New(logID, low, high).Proto()
}

type batchStorage map[int64]SourceList // Map of Revision to Sources

func (b batchStorage) ReadBatch(ctx context.Context, dirID string, rev int64) (*spb.MapMetadata, error) {
	return &spb.MapMetadata{Sources: b[rev]}, nil
}

func MustEncodeToken(t *testing.T, low water.Mark) string {
	t.Helper()

	rt := &rtpb.ReadToken{
		SliceIndex:     0,
		StartWatermark: low.Value(),
	}
	token, err := EncodeToken(rt)
	if err != nil {
		t.Fatalf("EncodeToken(%v): %v", rt, err)
	}
	return token
}

func TestListMutations(t *testing.T) {
	ctx := context.Background()
	dirID := "TestListMutations"
	logID := int64(0)
	fakeLogs := memory.NewMutationLogs()
	idx := make([]water.Mark, 0, 12)
	for i := int64(0); i < 12; i++ {
		// Send one entry.
		ws, err := fakeLogs.SendBatch(ctx, dirID, logID, genEntryUpdates(t, i, i+1))
		if err != nil {
			t.Fatal(err)
		}
		idx = append(idx, ws)
	}

	fakeBatches := batchStorage{
		1: SourceList{newSource(0, idx[2], idx[7])},
		2: SourceList{newSource(0, idx[7], idx[11])},
	}

	for _, tc := range []struct {
		desc       string
		token      string
		pageSize   int32
		start, end int64
		wantNext   *rtpb.ReadToken
		wantErr    bool
	}{
		{desc: "first page", pageSize: 6, start: 2, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "large page", pageSize: 10, start: 2, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "partial", pageSize: 4, start: 2, end: 6, wantNext: &rtpb.ReadToken{StartWatermark: idx[6].Value()}},
		{desc: "large page with token", token: MustEncodeToken(t, idx[3]), pageSize: 10, start: 3, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "small page with token", token: MustEncodeToken(t, idx[3]), pageSize: 2, start: 3, end: 5,
			wantNext: &rtpb.ReadToken{StartWatermark: idx[5].Value()}},
		{desc: "invalid page token", token: "some_token", pageSize: 0, wantErr: true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			revision := int64(1)
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			e, err := newMiniEnv(ctx, t)
			if err != nil {
				t.Fatalf("newMiniEnv(): %v", err)
			}
			defer e.Close()
			e.srv.logs = &fakeLogs
			e.srv.batches = fakeBatches

			if !tc.wantErr {
				e.s.Map.EXPECT().GetLeavesByRevision(gomock.Any(),
					matchers.ProtoEqual(
						&tpb.GetMapLeavesByRevisionRequest{
							MapId: mapID,
							Index: genIndexes(tc.start, tc.end),
						})).Return(&tpb.GetMapLeavesResponse{
					MapLeafInclusion: genInclusions(tc.start, tc.end),
				}, nil)
			}

			resp, err := e.srv.ListMutations(ctx, &pb.ListMutationsRequest{
				DirectoryId: directoryID,
				Revision:    revision,
				PageToken:   tc.token,
				PageSize:    tc.pageSize,
			})
			if got, want := err != nil, tc.wantErr; got != want {
				t.Fatalf("GetMutations: %v, wantErr %v", err, want)
			}
			if err != nil {
				return
			}

			got := []*pb.EntryUpdate{}
			for _, m := range resp.Mutations {
				got = append(got, &pb.EntryUpdate{Mutation: m.Mutation})
			}

			if want := genEntryUpdates(t, tc.start, tc.end); !cmp.Equal(
				got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("got: %v, want: %v, diff: \n%v", got, want, cmp.Diff(got, want))
			}

			var npt rtpb.ReadToken
			if err := DecodeToken(resp.NextPageToken, &npt); err != nil {
				t.Errorf("DecodeToken(): %v", err)
			}
			if !proto.Equal(&npt, tc.wantNext) {
				t.Errorf("resp.NextPageToken:%v-> %v, want %v", resp.NextPageToken, &npt, tc.wantNext)
			}
		})
	}
}
