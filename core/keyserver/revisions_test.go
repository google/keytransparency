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
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/mutator"

	protopb "github.com/golang/protobuf/ptypes/timestamp"
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

func TestGetRevisionStream(t *testing.T) {
	srv := &Server{}
	err := srv.GetRevisionStream(nil, nil)
	if got, want := status.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}

type batchStorage map[int64]SourceList // Map of Revision to Sources

func (b batchStorage) ReadBatch(ctx context.Context, dirID string, rev int64) (*spb.MapMetadata, error) {
	return &spb.MapMetadata{Sources: b[rev]}, nil
}

type mutations map[int64][]*mutator.LogMessage // Map of logID to Slice of LogMessages

func (m *mutations) Send(ctx context.Context, dirID string, _ int64, mutation ...*pb.EntryUpdate) (int64, time.Time, error) {
	return 0, time.Time{}, errors.New("unimplemented")
}

func (m *mutations) ReadLog(ctx context.Context, dirID string,
	logID int64, low, high time.Time, batchSize int32) ([]*mutator.LogMessage, error) {
	logShard := (*m)[logID]
	if low.UnixNano() > int64(len(logShard)) {
		return nil, fmt.Errorf("invalid argument: low: %v, want <= max watermark: %v", low, len(logShard))
	}
	count := high.UnixNano() - low.UnixNano()
	if count > int64(batchSize) {
		count = int64(batchSize)
	}
	if low.UnixNano()+count > int64(len(logShard)) {
		count = int64(len(logShard)) - low.UnixNano() + 1
	}
	return logShard[low.UnixNano() : low.UnixNano()+count], nil
}

func MustEncodeToken(t *testing.T, low time.Time) string {
	t.Helper()

	st, err := ptypes.TimestampProto(low)
	if err != nil {
		t.Fatal(err)
	}
	rt := &rtpb.ReadToken{
		SliceIndex: 0,
		StartTime:  st,
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
		1: SourceList{{LogId: 0, LowestInclusive: 2, HighestExclusive: 7}},
		2: SourceList{{LogId: 0, LowestInclusive: 7, HighestExclusive: 11}},
	}

	fakeLogs := make(mutations)
	for _, sources := range fakeBatches {
		for _, source := range sources {
			extendBy := source.HighestExclusive - int64(len(fakeLogs[source.LogId]))
			if extendBy > 0 {
				fakeLogs[source.LogId] = append(fakeLogs[source.LogId], make([]*mutator.LogMessage, extendBy)...)
			}
			for i := source.LowestInclusive; i < source.HighestExclusive; i++ {
				fakeLogs[source.LogId][i] = &mutator.LogMessage{
					ID: time.Unix(0, i*int64(time.Nanosecond)),
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
		wantNext   *rtpb.ReadToken
		wantErr    bool
	}{
		{desc: "exact page", pageSize: 6, start: 2, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "large page", pageSize: 10, start: 2, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "partial", pageSize: 4, start: 2, end: 6, wantNext: &rtpb.ReadToken{StartTime: &protopb.Timestamp{Nanos: 6}}},
		{desc: "large page with token", token: MustEncodeToken(t, time.Unix(0, 3)), pageSize: 10, start: 3, end: 7, wantNext: &rtpb.ReadToken{}},
		{desc: "small page with token", token: MustEncodeToken(t, time.Unix(0, 3)), pageSize: 2, start: 3, end: 5,
			wantNext: &rtpb.ReadToken{StartTime: &protopb.Timestamp{Nanos: 5}}},
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
			mtns := fakeLogs[0][tc.start:tc.end]
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
			if !proto.Equal(&npt, tc.wantNext) {
				t.Errorf("resp.NextPageToken:%v-> %v, want %v", resp.NextPageToken, &npt, tc.wantNext)
			}
		})
	}
}
