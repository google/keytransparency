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

package client

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/trillian"
	"github.com/google/trillian/testonly/matchers"
	"github.com/google/trillian/types"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func TestMapRevisionFor(t *testing.T) {
	for _, tc := range []struct {
		treeSize     uint64
		wantRevision uint64
		wantErr      error
	}{
		{treeSize: 1, wantRevision: 0},
		{treeSize: 0, wantRevision: 0, wantErr: ErrLogEmpty},
		{treeSize: ^uint64(0), wantRevision: ^uint64(0) - 1},
	} {
		revision, err := mapRevisionFor(&types.LogRootV1{TreeSize: tc.treeSize})
		if got, want := revision, tc.wantRevision; got != want {
			t.Errorf("mapRevisionFor(%v).Revision: %v, want: %v", tc.treeSize, got, want)
		}
		if got, want := err, tc.wantErr; got != want {
			t.Errorf("mapRevisionFor(%v).err: %v, want: %v", tc.treeSize, got, want)
		}
	}
}

func TestCompressHistory(t *testing.T) {
	for _, tc := range []struct {
		desc    string
		roots   map[uint64][]byte
		want    map[uint64][]byte
		wantErr error
	}{
		{
			desc: "Single",
			roots: map[uint64][]byte{
				1: []byte("a"),
			},
			want: map[uint64][]byte{
				1: []byte("a"),
			},
		},
		{
			desc: "Compress",
			roots: map[uint64][]byte{
				0: []byte("a"),
				1: []byte("a"),
				2: []byte("a"),
			},
			want: map[uint64][]byte{
				0: []byte("a"),
			},
		},
		{
			desc: "Not Contiguous",
			roots: map[uint64][]byte{
				0: []byte("a"),
				2: []byte("a"),
			},
			wantErr: ErrNonContiguous,
		},
		{
			desc: "Complex",
			roots: map[uint64][]byte{
				1: []byte("a"),
				2: []byte("a"),
				3: []byte("b"),
				4: []byte("b"),
				5: []byte("c"),
			},
			want: map[uint64][]byte{
				1: []byte("a"),
				3: []byte("b"),
				5: []byte("c"),
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := CompressHistory(tc.roots)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("compressHistory(): %#v, want %#v", got, tc.want)
			}
			if err != tc.wantErr {
				t.Errorf("compressHistory(): %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestPaginateHistory(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	appID := "fakeapp"
	userID := "fakeuser"

	type request struct {
		wantStart int64
		wantSize  int32
		next      int64
		items     []*pb.GetEntryResponse
	}

	for _, tc := range []struct {
		desc       string
		start, end int64
		reqs       []request
		pageSize   int32
		wantErr    error
	}{
		{
			desc:    "incomplete",
			end:     10,
			reqs:    []request{{}},
			wantErr: ErrIncomplete,
		},
		{
			desc: "1Item",
			end:  0,
			reqs: []request{
				{items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{0}}},
				}},
			},
		},
		{
			desc:  "3Times",
			start: 0,
			end:   10,
			reqs: []request{
				{wantStart: 0, next: 5, items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{0}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{1}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{2}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{3}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{4}}},
				}},
				{wantStart: 5, next: 10, items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{5}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{6}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{7}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{8}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{9}}},
				}},
				{wantStart: 10, next: 0, items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{10}}},
				}},
			},
		},
		{
			desc:     "pageSize",
			start:    0,
			end:      5,
			pageSize: 3,
			reqs: []request{
				// The value of next is opaque to the client.
				{wantStart: 0, wantSize: 3, next: 1, items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{0}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{1}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{2}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{3}}},
				}},
				{wantStart: 1, wantSize: 2, next: 0, items: []*pb.GetEntryResponse{
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{5}}},
					{Smr: &trillian.SignedMapRoot{MapRoot: []byte{6}}},
				}},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()
			s, stop, err := testutil.NewMockKT(ctrl)
			if err != nil {
				t.Fatalf("NewMockKT(): %v", err)
			}
			defer stop()

			c := Client{
				Verifier: &fakeVerifier{},
				cli:      s.Client,
				pageSize: tc.pageSize,
			}

			for _, r := range tc.reqs {
				s.Server.EXPECT().ListEntryHistory(gomock.Any(), matchers.ProtoEqual(&pb.ListEntryHistoryRequest{
					AppId:    appID,
					UserId:   userID,
					Start:    r.wantStart,
					PageSize: r.wantSize,
				})).Return(&pb.ListEntryHistoryResponse{
					NextStart: r.next,
					Values:    r.items,
				}, nil)
			}

			if _, _, err = c.PaginateHistory(ctx, appID, userID, tc.start, tc.end); err != tc.wantErr {
				t.Errorf("PaginateHistory(): %v, want %v", err, tc.wantErr)
			}
		})
	}
}

type fakeVerifier struct{}

func (f *fakeVerifier) Index(vrfProof []byte, domainID string, appID string, userID string) ([]byte, error) {
	return make([]byte, 32), nil
}

func (f *fakeVerifier) VerifyGetEntryResponse(ctx context.Context, domainID string, appID string, userID string, trusted types.LogRootV1, in *pb.GetEntryResponse) (*types.MapRootV1, *types.LogRootV1, error) {
	smr, err := f.VerifySignedMapRoot(in.Smr)
	return smr, &types.LogRootV1{}, err
}

func (f *fakeVerifier) VerifyEpoch(in *pb.Epoch, trusted types.LogRootV1) (*types.LogRootV1, *types.MapRootV1, error) {
	smr, err := f.VerifySignedMapRoot(in.Smr)
	return &types.LogRootV1{}, smr, err
}

func (f *fakeVerifier) VerifySignedMapRoot(smr *trillian.SignedMapRoot) (*types.MapRootV1, error) {
	return &types.MapRootV1{Revision: uint64(smr.MapRoot[0])}, nil
}
