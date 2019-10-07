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

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/keytransparency/core/testutil"
	"github.com/google/trillian"
	"github.com/google/trillian/types"
	"github.com/kylelemons/godebug/pretty"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	userID := "fakeuser"

	srv := &fakeKeyServer{
		revisions: map[int64]*pb.GetUserResponse{
			0:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{0}}}}},
			1:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{1}}}}},
			2:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{2}}}}},
			3:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{3}}}}},
			4:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{4}}}}},
			5:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{5}}}}},
			6:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{6}}}}},
			7:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{7}}}}},
			8:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{8}}}}},
			9:  {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{9}}}}},
			10: {Revision: &pb.Revision{MapRoot: &pb.MapRoot{MapRoot: &trillian.SignedMapRoot{MapRoot: []byte{10}}}}},
		},
	}
	s, stop, err := testutil.NewFakeKT(srv)
	if err != nil {
		t.Fatalf("NewFakeKT(): %v", err)
	}
	defer stop()

	for _, tc := range []struct {
		desc       string
		start, end int64
		wantErr    error
		wantValues map[uint64][]byte
	}{
		{
			desc:    "incomplete",
			start:   9,
			end:     15,
			wantErr: ErrIncomplete,
		},
		{
			desc: "1Item",
			end:  0,
			wantValues: map[uint64][]byte{
				0: nil,
			},
		},
		{
			desc: "2Items",
			end:  1,
			wantValues: map[uint64][]byte{
				0: nil,
				1: nil,
			},
		},
		{
			desc:  "3Times",
			start: 0,
			end:   10,
			wantValues: map[uint64][]byte{
				0:  nil,
				1:  nil,
				2:  nil,
				3:  nil,
				4:  nil,
				5:  nil,
				6:  nil,
				7:  nil,
				8:  nil,
				9:  nil,
				10: nil,
			},
		},
		{
			desc:  "pageSize",
			start: 0,
			end:   5,
			wantValues: map[uint64][]byte{
				0: nil,
				1: nil,
				2: nil,
				3: nil,
				4: nil,
				5: nil,
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			c := Client{
				VerifierInterface: &fakeVerifier{},
				cli:               s.Client,
			}

			_, values, err := c.PaginateHistory(ctx, userID, tc.start, tc.end)
			if err != tc.wantErr {
				t.Errorf("PaginateHistory(): %v, want %v", err, tc.wantErr)
			}
			if got, want := values, tc.wantValues; !reflect.DeepEqual(got, want) {
				t.Errorf("PaginateHistory().values: \n%#v, want \n%#v, diff: \n%v",
					got, want, pretty.Compare(got, want))
			}
		})
	}
}

type fakeKeyServer struct {
	revisions map[int64]*pb.GetUserResponse
}

func (f *fakeKeyServer) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	currentRevision := int64(len(f.revisions)) - 1 // len(1) contains map revision 0.
	if in.PageSize > 5 || in.PageSize == 0 {
		in.PageSize = 5 // Test maximum page size limits.
	}
	if in.Start+int64(in.PageSize) > currentRevision {
		in.PageSize = int32(currentRevision - in.Start + 1)
	}

	values := make([]*pb.GetUserResponse, in.PageSize)
	for i := range values {
		values[i] = f.revisions[in.Start+int64(i)]
	}
	next := in.Start + int64(len(values))
	if next > currentRevision {
		next = 0 // no more!
	}

	return &pb.ListEntryHistoryResponse{
		Values:    values,
		NextStart: next,
	}, nil
}

func (f *fakeKeyServer) ListUserRevisions(ctx context.Context, in *pb.ListUserRevisionsRequest) (
	*pb.ListUserRevisionsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) BatchListUserRevisions(ctx context.Context, in *pb.BatchListUserRevisionsRequest) (
	*pb.BatchListUserRevisionsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) GetDirectory(context.Context, *pb.GetDirectoryRequest) (*pb.Directory, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) GetRevision(context.Context, *pb.GetRevisionRequest) (*pb.Revision, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) GetLatestRevision(context.Context, *pb.GetLatestRevisionRequest) (*pb.Revision, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) GetRevisionStream(*pb.GetRevisionRequest, pb.KeyTransparency_GetRevisionStreamServer) error {
	return status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) ListMutations(context.Context, *pb.ListMutationsRequest) (*pb.ListMutationsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) ListMutationsStream(*pb.ListMutationsRequest, pb.KeyTransparency_ListMutationsStreamServer) error {
	return status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) GetUser(context.Context, *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) BatchGetUser(context.Context, *pb.BatchGetUserRequest) (*pb.BatchGetUserResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) BatchGetUserIndex(context.Context,
	*pb.BatchGetUserIndexRequest) (*pb.BatchGetUserIndexResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) QueueEntryUpdate(context.Context, *pb.UpdateEntryRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (f *fakeKeyServer) BatchQueueUserUpdate(context.Context, *pb.BatchQueueUserUpdateRequest) (*empty.Empty, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

type fakeVerifier struct{}

func (f *fakeVerifier) Index(vrfProof []byte, directoryID, userID string) ([]byte, error) {
	return make([]byte, 32), nil
}

func (f *fakeVerifier) LastVerifiedLogRoot() *pb.LogRootRequest {
	return &pb.LogRootRequest{}
}

func (f *fakeVerifier) VerifyLogRoot(req *pb.LogRootRequest, slr *pb.LogRoot) (*types.LogRootV1, error) {
	return &types.LogRootV1{}, nil
}

func (f *fakeVerifier) VerifyMapRevision(logRoot *types.LogRootV1, smr *pb.MapRoot) (*types.MapRootV1, error) {
	return &types.MapRootV1{Revision: uint64(smr.MapRoot.MapRoot[0])}, nil
}

func (f *fakeVerifier) VerifyMapLeaf(directoryID, userID string,
	in *pb.MapLeaf, smr *types.MapRootV1) error {
	return nil
}

func (f *fakeVerifier) VerifyGetUser(req *pb.GetUserRequest, resp *pb.GetUserResponse) error {
	return nil
}

func (f *fakeVerifier) VerifyBatchGetUser(req *pb.BatchGetUserRequest, resp *pb.BatchGetUserResponse) error {
	return nil
}
