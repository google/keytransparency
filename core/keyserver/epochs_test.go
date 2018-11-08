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
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/mutator"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	rtpb "github.com/google/keytransparency/core/keyserver/readtoken_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const (
	directoryID = "directory"
)

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(%T): %v", p, err)
	}
	return b
}

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
	for i := start + 1; i <= end; i++ {
		indexes = append(indexes, []byte(fmt.Sprintf("key_%v", i)))
	}
	return indexes
}

func TestGetRevisionStream(t *testing.T) {
	srv := &Server{}
	err := srv.GetRevisionStream(nil, nil)
	if got, want := status.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}

type batchStorage map[int64]SourceMap // Map of Revision to Sources

func (b batchStorage) ReadBatch(ctx context.Context, dirID string, rev int64) (*spb.MapMetadata, error) {
	return &spb.MapMetadata{Sources: b[rev]}, nil
}

type mutations map[int64][]*mutator.LogMessage // Map of logID to Slice of LogMessages

func (m *mutations) Send(ctx context.Context, dirID string, mutation *pb.EntryUpdate) error {
	return errors.New("unimplemented")
}

func (m *mutations) ReadLog(ctx context.Context, dirID string,
	logID, low, high int64, batchSize int32) ([]*mutator.LogMessage, error) {
	logShard := (*m)[logID]
	low = low + 1 // Begin exclusive
	if low > int64(len(logShard)) {
		return nil, fmt.Errorf("invalid argument: low: %v, want < max watermark: %v", low, len(*m))
	}
	count := high + 1 - low // End inclusive
	if count > int64(batchSize) {
		count = int64(batchSize)
	}
	if low+count > int64(len(logShard)) {
		count = int64(len(logShard)) - low + 1
	}
	return logShard[low : low+count], nil
}

func MustEncodeToken(t *testing.T, low int64) string {
	t.Helper()
	rt := &rtpb.ReadToken{
		ShardId:      0,
		LowWatermark: low,
	}
	token, err := EncodeToken(rt)
	if err != nil {
		t.Fatalf("EncodeToken(%v): %v", rt, err)
	}
	return token
}

func TestListMutations(t *testing.T) {
	ctx := context.Background()
	fakeBatches := batchStorage{
		1: SourceMap{0: {LowestWatermark: 1, HighestWatermark: 6}},
		2: SourceMap{0: {LowestWatermark: 6, HighestWatermark: 10}},
	}

	fakeLogs := make(mutations)
	for _, sources := range fakeBatches {
		for logID, source := range sources {
			// Extend the log to hold at least source.HighestWatermark
			extendBy := 1 + source.HighestWatermark - int64(len(fakeLogs[logID]))
			if extendBy > 0 {
				fakeLogs[logID] = append(fakeLogs[logID], make([]*mutator.LogMessage, extendBy)...)
			}
			// LowestWatermark is *exclusive*, so we start with the next index.
			// HighestWatermark is *inclusive*, so we include that one before stopping.
			for i := source.LowestWatermark + 1; i <= source.HighestWatermark; i++ {
				fakeLogs[logID][i] = &mutator.LogMessage{
					ID: i,
					Mutation: &pb.SignedEntry{
						Entry: mustMarshal(t, &pb.Entry{
							Index:      []byte(fmt.Sprintf("key_%v", i)),
							Commitment: []byte(fmt.Sprintf("value_%v", i)),
						}),
					},
				}
			}
		}
	}

	for _, tc := range []struct {
		desc       string
		token      string
		pageSize   int32
		start, end int64
		wantNext   rtpb.ReadToken
		wantErr    bool
	}{
		{desc: "exact page", pageSize: 6, start: 1, end: 6},
		{desc: "large page", pageSize: 10, start: 1, end: 6},
		{desc: "partial", pageSize: 4, start: 1, end: 5, wantNext: rtpb.ReadToken{LowWatermark: 5}},
		{desc: "large page with token", token: MustEncodeToken(t, 2), pageSize: 10, start: 2, end: 6},
		{desc: "small page with token", token: MustEncodeToken(t, 2), pageSize: 2, start: 2, end: 4,
			wantNext: rtpb.ReadToken{LowWatermark: 4}},
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
					&tpb.GetMapLeavesByRevisionRequest{
						MapId: mapID,
						Index: genIndexes(tc.start, tc.end),
					}).Return(&tpb.GetMapLeavesResponse{
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
			mtns := fakeLogs[0][tc.start+1 : tc.end+1]
			if got, want := len(resp.Mutations), len(mtns); got != want {
				t.Fatalf("len(resp.Mutations):%v, want %v", got, want)
			}
			for i, mut := range resp.Mutations {
				if got, want := mut.Mutation, mtns[i].Mutation; !proto.Equal(got, want) {
					t.Errorf("resp.Mutations[i].Update:%v, want %v", got, want)
				}
			}

			var npt rtpb.ReadToken
			if err := DecodeToken(resp.NextPageToken, &npt); err != nil {
				t.Errorf("DecodeToken(): %v", err)
			}
			if !proto.Equal(&npt, &tc.wantNext) {
				t.Errorf("resp.NextPageToken:%v-> %v, want %v", resp.NextPageToken, npt, tc.wantNext)
			}
		})
	}
}
