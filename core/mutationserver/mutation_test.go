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

// Package mutation implements the monitor service. This package contains the
// core functionality.
package mutationserver

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	tpb "github.com/google/trillian"
)

const (
	domainID = "domain"
)

func updates(t *testing.T, start, end int) []*pb.EntryUpdate {
	if start > end {
		t.Fatalf("start=%v > end=%v", start, end)
	}
	kvs := make([]*pb.EntryUpdate, 0, end-start)
	for i := start; i <= end; i++ {
		kvs = append(kvs, &pb.EntryUpdate{
			Mutation: &pb.Entry{
				Index:      []byte(fmt.Sprintf("key_%v", i)),
				Commitment: []byte(fmt.Sprintf("value_%v", i)),
			},
		})
	}
	return kvs
}

func prepare(ctx context.Context, t *testing.T, mapID int64, mutations mutator.MutationStorage, tmap *fake.MapServer) {
	createEpoch(ctx, t, mapID, mutations, tmap, 1, 1, 6)
	createEpoch(ctx, t, mapID, mutations, tmap, 2, 7, 10)
}

func createEpoch(ctx context.Context, t *testing.T, mapID int64, mutations mutator.MutationStorage, tmap *fake.MapServer, epoch int64, start, end int) {
	kvs := updates(t, start, end)
	for _, kv := range kvs {
		if _, err := mutations.Write(nil, mapID, kv); err != nil {
			t.Fatalf("mutations.Write failed: %v", err)
		}
	}
	tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		Metadata: mustMetadataAsAny(t, &pb.MapperMetadata{
			HighestFullyCompletedSeq: int64(end),
		}),
	})
}

func mustMetadataAsAny(t *testing.T, meta *pb.MapperMetadata) *any.Any {
	m, err := internal.MetadataAsAny(meta)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestGetMutationsStream(t *testing.T) {
	srv := &Server{}
	err := srv.GetMutationsStream(nil, nil)
	if got, want := grpc.Code(err), codes.Unimplemented; got != want {
		t.Errorf("GetMutationsStream(_, _): %v, want %v", got, want)
	}
}

func TestGetMutations(t *testing.T) {
	ctx := context.Background()
	mapID := int64(2)
	fakeMutations := fake.NewMutationStorage()
	fakeAdmin := fake.NewAdminStorage()
	fakeMap := fake.NewTrillianMapClient()
	if err := fakeAdmin.Write(ctx, domainID, mapID, 0, nil, nil, 1*time.Second, 5*time.Second); err != nil {
		t.Fatalf("admin.Write(): %v", err)
	}
	prepare(ctx, t, mapID, fakeMutations, fakeMap)

	for _, tc := range []struct {
		description string
		epoch       int64
		token       string
		pageSize    int32
		mutations   []*pb.EntryUpdate
		nextToken   string
		success     bool
	}{
		{"working case complete epoch 1", 1, "", 6, updates(t, 1, 6), "", true},
		{"working case complete epoch 2", 2, "", 4, updates(t, 7, 10), "", true},
		{"working case partial epoch 1", 1, "", 4, updates(t, 1, 4), "4", true},
		{"working case partial epoch 2", 2, "", 3, updates(t, 7, 9), "9", true},
		{"working case larger page size and no token", 1, "", 10, updates(t, 1, 6), "", true},
		{"working case larger page size with token", 1, "2", 10, updates(t, 3, 6), "", true},
		{"working case with page token", 1, "4", 2, updates(t, 5, 6), "", true},
		{"working case with page token and small page size", 1, "2", 2, updates(t, 3, 4), "4", true},
		{"invalid page token", 1, "some_token", 0, nil, "", false},
	} {
		t.Run(tc.description, func(t *testing.T) {
			srv := New(fakeAdmin, fake.NewFakeTrillianLogClient(), fakeMap, fakeMutations, &fakeFactory{})
			resp, err := srv.GetMutations(ctx, &pb.GetMutationsRequest{
				DomainId:  domainID,
				Epoch:     tc.epoch,
				PageToken: tc.token,
				PageSize:  tc.pageSize,
			})
			if got, want := err == nil, tc.success; got != want {
				t.Errorf("GetMutations: %v, wantErr %v", err, want)
				return
			}
			if err != nil {
				return
			}
			if got, want := resp.Epoch, tc.epoch; got != want {
				t.Errorf("resp.Epoch=%v, want %v", got, want)
			}
			if got, want := len(resp.Mutations), len(tc.mutations); got != want {
				t.Errorf("len(resp.Mutations)=%v, want %v", got, want)
			}
			for i := 0; i < len(resp.Mutations); i++ {
				if got, want := resp.Mutations[i].Mutation, tc.mutations[i].Mutation; !proto.Equal(got, want) {
					t.Errorf("resp.Mutations[i].Update=%v, want %v", got, want)
				}
			}
			if got, want := resp.NextPageToken, tc.nextToken; got != want {
				t.Errorf("resp.NextPageToken=%v, %v", got, want)
			}
		})
	}
}

func TestLowestSequenceNumber(t *testing.T) {
	ctx := context.Background()
	fakeMutations := fake.NewMutationStorage()
	fakeMap := fake.NewTrillianMapClient()
	fakeAdmin := &fake.AdminStorage{}
	mapID := int64(1)
	prepare(ctx, t, mapID, fakeMutations, fakeMap)

	for _, tc := range []struct {
		token     string
		epoch     int64
		lowestSeq uint64
		success   bool
	}{
		{"", 0, 0, true},
		{"4", 0, 4, true},
		{"4", 1, 4, true},
		{"some_token", 0, 0, false},
		{"", 1, 6, true},
	} {
		srv := New(fakeAdmin, fake.NewFakeTrillianLogClient(), fakeMap, fakeMutations, &fakeFactory{})
		seq, err := srv.lowestSequenceNumber(ctx, mapID, tc.token, tc.epoch)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("lowestSequenceNumber(%v, %v): err=%v, want %v", tc.token, tc.epoch, got, want)
		}
		if got, want := seq, tc.lowestSeq; got != want {
			t.Errorf("lowestSequenceNumber(%v, %v)=%v, want %v", tc.token, tc.epoch, got, want)
		}
	}
}

// transaction.Txn fake.
type fakeTxn struct{}

func (*fakeTxn) Prepare(query string) (*sql.Stmt, error) { return nil, nil }
func (*fakeTxn) Commit() error                           { return nil }
func (*fakeTxn) Rollback() error                         { return nil }

// transaction.Factory fake.
type fakeFactory struct{}

func (fakeFactory) NewTxn(ctx context.Context) (transaction.Txn, error) {
	return &fakeTxn{}, nil
}
