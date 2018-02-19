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

	"github.com/google/keytransparency/core/fake"

	"github.com/golang/mock/gomock"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tpb "github.com/google/trillian"
)

const (
	domainID = "domain"
)

func genInclusions(start, end int) []*tpb.MapLeafInclusion {
	ret := make([]*tpb.MapLeafInclusion, end-start+1)
	for i := range ret {
		ret[i] = &tpb.MapLeafInclusion{}
	}
	return ret
}

func genIndexes(start, end int) [][]byte {
	indexes := make([][]byte, 0, end-start)
	for i := start; i <= end; i++ {
		indexes = append(indexes, []byte(fmt.Sprintf("key_%v", i)))
	}
	return indexes
}

func genMutations(start, end int) []*pb.Entry {
	mutations := make([]*pb.Entry, 0, end-start)
	for i := start; i <= end; i++ {
		mutations = append(mutations, &pb.Entry{
			Index:      []byte(fmt.Sprintf("key_%v", i)),
			Commitment: []byte(fmt.Sprintf("value_%v", i)),
		})
	}
	return mutations
}

func TestGetEpochStream(t *testing.T) {
	srv := &Server{}
	err := srv.GetEpochStream(nil, nil)
	if got, want := status.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}

func TestListMutations(t *testing.T) {
	ctx := context.Background()
	fakeMutations := fake.NewMutationStorage()

	// Test setup.
	for _, rev := range []struct {
		epoch      int64
		start, end int
	}{
		{epoch: 1, start: 1, end: 6},
		{epoch: 2, start: 7, end: 10},
	} {
		if err := fakeMutations.WriteBatch(ctx, domainID, rev.epoch, genMutations(rev.start, rev.end)); err != nil {
			t.Fatalf("Test setup failed: %v", err)
		}
	}

	for _, tc := range []struct {
		desc       string
		epoch      int64
		token      string
		pageSize   int32
		start, end int
		wantNext   string
		wantErr    bool
	}{
		{desc: "exact page", epoch: 1, token: "", pageSize: 6, start: 1, end: 6, wantNext: "7"},
		{desc: "large page", epoch: 1, token: "", pageSize: 10, start: 1, end: 6, wantNext: ""},
		{desc: "partial epoch 1", epoch: 1, token: "", pageSize: 4, start: 1, end: 4, wantNext: "5"},
		{desc: "large page with token", epoch: 1, token: "2", pageSize: 10, start: 3, end: 6, wantNext: ""},
		{desc: "smal page with token", epoch: 1, token: "2", pageSize: 2, start: 3, end: 4, wantNext: "5"},
		{desc: "invalid page token", epoch: 1, token: "some_token", pageSize: 0, wantNext: "", wantErr: true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
			defer cancel()
			e, err := newMiniEnv(ctx, t)
			if err != nil {
				t.Fatalf("newMiniEnv(): %v", err)
			}
			defer e.Close()
			e.srv.mutations = fakeMutations

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
				DomainId:  domainID,
				Epoch:     tc.epoch,
				PageToken: tc.token,
				PageSize:  tc.pageSize,
			})
			if got, want := err != nil, tc.wantErr; got != want {
				t.Fatalf("GetMutations: %v, wantErr %v", err, want)
			}
			if err != nil {
				return
			}
			mtns := genMutations(tc.start, tc.end)
			if got, want := len(resp.Mutations), len(mtns); got != want {
				t.Fatalf("len(resp.Mutations):%v, want %v", got, want)
			}
			for i, mut := range resp.Mutations {
				if got, want := mut.Mutation, mtns[i]; !proto.Equal(got, want) {
					t.Errorf("resp.Mutations[i].Update:%v, want %v", got, want)
				}
			}
			if got, want := resp.NextPageToken, tc.wantNext; got != want {
				t.Errorf("resp.NextPageToken:%v, want %v", got, want)
			}
		})
	}
}
