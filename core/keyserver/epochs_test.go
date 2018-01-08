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

	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tpb "github.com/google/trillian"
)

const (
	domainID = "domain"
)

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

func prepare(ctx context.Context, domainID string, m mutator.MutationStorage, tmap *fake.MapServer) error {
	for _, rev := range []struct {
		epoch      int64
		start, end int
	}{
		{epoch: 1, start: 1, end: 6},
		{epoch: 2, start: 7, end: 10},
	} {
		if err := m.WriteBatch(ctx, domainID, rev.epoch, genMutations(rev.start, rev.end)); err != nil {
			return err
		}
		tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{})

	}
	return nil
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
	mapID := int64(2)
	fakeMutations := fake.NewMutationStorage()
	fakeAdmin := fake.NewDomainStorage()
	fakeMap := fake.NewTrillianMapClient()
	fakeLog := fake.NewTrillianLogClient()
	if err := fakeAdmin.Write(ctx, &domain.Domain{
		DomainID:    domainID,
		MapID:       mapID,
		MinInterval: 1 * time.Second,
		MaxInterval: 5 * time.Second,
	}); err != nil {
		t.Fatalf("admin.Write(): %v", err)
	}
	if err := prepare(ctx, domainID, fakeMutations, fakeMap); err != nil {
		t.Fatalf("Test setup failed: %v", err)
	}

	for _, tc := range []struct {
		desc     string
		epoch    int64
		token    string
		pageSize int32
		mtns     []*pb.Entry
		wantNext string
		wantErr  bool
	}{
		{desc: "exact page", epoch: 1, token: "", pageSize: 6, mtns: genMutations(1, 6), wantNext: "7"},
		{desc: "large page", epoch: 1, token: "", pageSize: 10, mtns: genMutations(1, 6), wantNext: ""},
		{desc: "partial epoch 1", epoch: 1, token: "", pageSize: 4, mtns: genMutations(1, 4), wantNext: "5"},
		{desc: "large page with token", epoch: 1, token: "2", pageSize: 10, mtns: genMutations(3, 6), wantNext: ""},
		{desc: "smal page with token", epoch: 1, token: "2", pageSize: 2, mtns: genMutations(3, 4), wantNext: "5"},
		{desc: "invalid page token", epoch: 1, token: "some_token", pageSize: 0, mtns: nil, wantNext: "", wantErr: true},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			srv := &Server{
				domains:   fakeAdmin,
				tlog:      fakeLog,
				tmap:      fakeMap,
				mutations: fakeMutations,
			}
			resp, err := srv.ListMutations(ctx, &pb.ListMutationsRequest{
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
			if got, want := len(resp.Mutations), len(tc.mtns); got != want {
				t.Fatalf("len(resp.Mutations):%v, want %v", got, want)
			}
			for i, mut := range resp.Mutations {
				if got, want := mut.Mutation, tc.mtns[i]; !proto.Equal(got, want) {
					t.Errorf("resp.Mutations[i].Update:%v, want %v", got, want)
				}
			}
			if got, want := resp.NextPageToken, tc.wantNext; got != want {
				t.Errorf("resp.NextPageToken:%v, want %v", got, want)
			}
		})
	}
}
