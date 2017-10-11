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
package mutation

import (
	"context"
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/transaction"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/grpc"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	"github.com/google/trillian"
)

const (
	logID = 0
	mapID = 0
)

func signedKV(t *testing.T, start, end int) []*tpb.Entry {
	if start > end {
		t.Fatalf("start=%v > end=%v", start, end)
	}
	kvs := make([]*tpb.Entry, 0, end-start)
	for i := start; i <= end; i++ {
		kvs = append(kvs, &tpb.Entry{
			Index:      []byte(fmt.Sprintf("key_%v", i)),
			Commitment: []byte(fmt.Sprintf("value_%v", i)),
		})
	}
	return kvs
}

func prepare(t *testing.T, mutations *fakeMutation, fakeMap *fakeTrillianMapClient) {
	createEpoch(t, mutations, fakeMap, 1, 1, 6)
	createEpoch(t, mutations, fakeMap, 2, 7, 10)
}

func createEpoch(t *testing.T, mutations *fakeMutation, fakeMap *fakeTrillianMapClient, epoch int64, start, end int) {
	kvs := signedKV(t, start, end)
	for _, kv := range kvs {
		if _, err := mutations.Write(nil, kv); err != nil {
			t.Fatalf("mutations.Write failed: %v", err)
		}
	}
	fakeMap.tmap[epoch] = &trillian.SignedMapRoot{
		Metadata: mustMetadataAsAny(t, &tpb.MapperMetadata{
			HighestFullyCompletedSeq: int64(end),
		}),
		MapRevision: epoch,
	}
}

func mustMetadataAsAny(t *testing.T, meta *tpb.MapperMetadata) *any.Any {
	m, err := internal.MetadataAsAny(meta)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestGetMutations(t *testing.T) {
	ctx := context.Background()
	fakeMutations := &fakeMutation{}
	fakeMap := newFakeTrillianMapClient()
	prepare(t, fakeMutations, fakeMap)

	for _, tc := range []struct {
		description string
		epoch       int64
		token       string
		pageSize    int32
		mutations   []*tpb.Entry
		nextToken   string
		success     bool
	}{
		{"working case complete epoch 1", 1, "", 6, signedKV(t, 1, 6), "", true},
		{"working case complete epoch 2", 2, "", 4, signedKV(t, 7, 10), "", true},
		{"working case partial epoch 1", 1, "", 4, signedKV(t, 1, 4), "4", true},
		{"working case partial epoch 2", 2, "", 3, signedKV(t, 7, 9), "9", true},
		{"working case larger page size and no token", 1, "", 10, signedKV(t, 1, 6), "", true},
		{"working case larger page size with token", 1, "2", 10, signedKV(t, 3, 6), "", true},
		{"working case with page token", 1, "4", 2, signedKV(t, 5, 6), "", true},
		{"working case with page token and small page size", 1, "2", 2, signedKV(t, 3, 4), "4", true},
		{"invalid page token", 1, "some_token", 0, nil, "", false},
	} {
		srv := New(logID, mapID, fake.NewFakeTrillianLogClient(), fakeMap, fakeMutations, &fakeFactory{})
		resp, err := srv.GetMutations(ctx, &tpb.GetMutationsRequest{
			Epoch:     tc.epoch,
			PageToken: tc.token,
			PageSize:  tc.pageSize,
		})
		if got, want := err == nil, tc.success; got != want {
			t.Fatalf("%v: GetMutations: err=%v, want %v", tc.description, got, want)
		}
		if err != nil {
			continue
		}
		if got, want := resp.Epoch, tc.epoch; got != want {
			t.Errorf("%v: resp.Epoch=%v, want %v", tc.description, got, want)
		}
		if got, want := len(resp.Mutations), len(tc.mutations); got != want {
			t.Errorf("%v: len(resp.Mutations)=%v, want %v", tc.description, got, want)
		}
		for i := 0; i < len(resp.Mutations); i++ {
			if got, want := resp.Mutations[i].Mutation, tc.mutations[i]; !proto.Equal(got, want) {
				t.Errorf("%v: resp.Mutations[i].Update=%v, want %v", tc.description, got, want)
			}
		}
		if got, want := resp.NextPageToken, tc.nextToken; got != want {
			t.Errorf("%v: resp.NextPageToken=%v, %v", tc.description, got, want)
		}
	}
}

func TestLowestSequenceNumber(t *testing.T) {
	ctx := context.Background()
	fakeMutations := &fakeMutation{}
	fakeMap := newFakeTrillianMapClient()
	prepare(t, fakeMutations, fakeMap)

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
		srv := New(logID, mapID, fake.NewFakeTrillianLogClient(), fakeMap, fakeMutations, &fakeFactory{})
		seq, err := srv.lowestSequenceNumber(ctx, tc.token, tc.epoch)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("lowestSequenceNumber(%v, %v): err=%v, want %v", tc.token, tc.epoch, got, want)
		}
		if got, want := seq, tc.lowestSeq; got != want {
			t.Errorf("lowestSequenceNumber(%v, %v)=%v, want %v", tc.token, tc.epoch, got, want)
		}
	}
}

// trillian.TrillianMapClient fake.
type fakeTrillianMapClient struct {
	tmap map[int64]*trillian.SignedMapRoot
}

func newFakeTrillianMapClient() *fakeTrillianMapClient {
	return &fakeTrillianMapClient{
		tmap: make(map[int64]*trillian.SignedMapRoot),
	}
}

func (*fakeTrillianMapClient) GetLeaves(ctx context.Context, in *trillian.GetMapLeavesRequest, opts ...grpc.CallOption) (*trillian.GetMapLeavesResponse, error) {
	leaves := make([]*trillian.MapLeafInclusion, 0, len(in.Index))
	for _, index := range in.Index {
		leaves = append(leaves, &trillian.MapLeafInclusion{
			Leaf: &trillian.MapLeaf{
				Index: index,
			},
		})
	}
	return &trillian.GetMapLeavesResponse{
		MapLeafInclusion: leaves,
	}, nil
}

func (*fakeTrillianMapClient) SetLeaves(ctx context.Context, in *trillian.SetMapLeavesRequest, opts ...grpc.CallOption) (*trillian.SetMapLeavesResponse, error) {
	return nil, nil
}

func (*fakeTrillianMapClient) GetSignedMapRoot(ctx context.Context, in *trillian.GetSignedMapRootRequest, opts ...grpc.CallOption) (*trillian.GetSignedMapRootResponse, error) {
	return nil, nil
}

// GetSignedMapRootByRevision echos in.MapId in HighestFullyCompletedSeq.
func (m *fakeTrillianMapClient) GetSignedMapRootByRevision(ctx context.Context, in *trillian.GetSignedMapRootByRevisionRequest, opts ...grpc.CallOption) (*trillian.GetSignedMapRootResponse, error) {
	return &trillian.GetSignedMapRootResponse{
		MapRoot: m.tmap[in.Revision],
	}, nil
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

// mutator.Mutation fake.
type fakeMutation struct {
	mtns []*tpb.Entry
}

// sequence numbers are 1-based.
func (m *fakeMutation) ReadRange(txn transaction.Txn, startSequence, endSequence uint64, count int32) (uint64, []*tpb.Entry, error) {
	if startSequence > uint64(len(m.mtns)) {
		panic("startSequence > len(m.mtns)")
	}
	// Adjust endSequence.
	if endSequence-startSequence > uint64(count) {
		endSequence = startSequence + uint64(count)
	}
	if endSequence > uint64(len(m.mtns)) {
		endSequence = uint64(len(m.mtns))
	}
	return endSequence, m.mtns[startSequence:endSequence], nil
}

func (m *fakeMutation) ReadAll(txn transaction.Txn, startSequence uint64) (uint64, []*tpb.Entry, error) {
	return 0, nil, nil
}

func (m *fakeMutation) Write(txn transaction.Txn, mutation *tpb.Entry) (uint64, error) {
	m.mtns = append(m.mtns, mutation)
	return uint64(len(m.mtns)), nil
}
