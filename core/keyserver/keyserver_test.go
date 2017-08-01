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

package keyserver

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"
	"testing"

	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/mapserver"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/trillian"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	authzpb "github.com/google/keytransparency/core/proto/authorization"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

const (
	logID = int64(0)
	mapID = int64(0)
)

func TestListEntryHistory(t *testing.T) {
	profileCount := 25
	ctx := context.Background()
	for i, tc := range []struct {
		start       int64
		page        int32
		wantNext    int64
		wantHistory []int
		err         codes.Code
	}{
		{1, 1, 2, []int{1}, codes.OK},                                                            // one entry per page.
		{0, 1, 2, []int{1}, codes.OK},                                                            // start epoch is not set (will default to 1).
		{1, 10, 11, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, codes.OK},                              // 10 entries per page.
		{4, 10, 14, []int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, codes.OK},                           // start epoch is not 1.
		{1, 0, 17, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, codes.OK},       // zero page size.
		{20, 10, 0, []int{20, 21, 22, 23, 24}, codes.OK},                                         // end of list.
		{24, 10, 0, []int{24}, codes.OK},                                                         // requesting the very last entry.
		{1, 1000000, 17, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, codes.OK}, // DOS prevention.
		{40, 10, 0, []int{}, codes.InvalidArgument},                                              // start epoch is beyond current epoch.
		{-1, 1, 1, []int{0}, codes.InvalidArgument},                                              // start epoch is less than 0.
	} {
		// Test case setup.
		c := &fakeCommitter{make(map[string]*tpb.Committed)}
		tree := &fakeSparseHist{make(map[int64][]byte)}
		sths := &fakeSequenced{make([][]byte, 0)}
		mapsvr := mapserver.NewReadonly(mapID, tree, fakeFactory{}, sths)
		tlog := fake.NewFakeTrillianLogClient()
		tadmin := trillian.NewTrillianAdminClient(nil)

		srv := New(logID, tlog, mapID, mapsvr, tadmin, c, fakePrivateKey{}, fakeMutator{},
			authentication.NewFake(), fakeAuthz{}, fakeFactory{}, fakeMutation{})
		if err := addProfiles(profileCount, c, tree, sths); err != nil {
			t.Fatalf("addProfile(%v, _, _, _)=%v", profileCount, err)
		}

		// Run test case.
		req := &tpb.ListEntryHistoryRequest{
			UserId:   "",
			Start:    tc.start,
			PageSize: tc.page,
		}
		resp, err := srv.ListEntryHistory(ctx, req)
		if got, want := grpc.Code(err), tc.err; got != want {
			t.Errorf("%v: ListEntryHistory(%v): %v, want %v", i, req, err, tc.err)
		}
		// Skip the rest of the test if there is an error.
		if err != nil {
			continue
		}

		// Check next epoch.
		if got, want := resp.NextStart, tc.wantNext; got != want {
			fmt.Printf("tc: %+v", tc)
			t.Errorf("%v: NextEpoch=%v, want %v", i, got, want)
		}

		// Ensure that history has the correct number of entries.
		if got, want := len(resp.Values), len(tc.wantHistory); got != want {
			t.Errorf("%v: len(resp.Values)=%v, want %v", i, got, want)
			// Skip the rest of the test if the returned history is
			// not of the expected length.
			continue
		}

		if got := checkProfiles(tc.wantHistory, resp.Values); got != nil {
			t.Errorf("%v: checkProfiles(%v, _): %v, want nil", i, tc.wantHistory, got)
		}
	}
}

func addProfiles(count int, c *fakeCommitter, st *fakeSparseHist, sths appender.Local) error {
	profiles := make([][]byte, count)
	for i := range profiles {
		profiles[i] = []byte(fmt.Sprintf("bar%v", i))
		commitment := []byte{uint8(i)}

		// Fill the committer map.
		committed := &tpb.Committed{Data: profiles[i]}
		c.M[string(commitment)] = committed
		st.M[int64(i)] = commitment

		smr := &trillian.SignedMapRoot{
			MapRevision: int64(i),
		}
		if err := sths.Write(nil, 0, int64(i), smr); err != nil {
			return err
		}
	}
	return nil
}

// checkProfiles Ensure that the history has the correct entries in the correct
// order.
func checkProfiles(wantHistory []int, values []*tpb.GetEntryResponse) error {
	for i, tag := range wantHistory {
		if got, want := values[i].Committed.Data,
			[]byte(fmt.Sprintf("bar%v", tag)); !bytes.Equal(got, want) {
			return fmt.Errorf("%v: Invalid profile: %v, want %v", i, got, want)
		}
	}
	return nil
}

///////////
// Fakes //
///////////

type fakeCommitter struct {
	M map[string]*tpb.Committed
}

func (*fakeCommitter) Write(ctx context.Context, commitment []byte, committed *tpb.Committed) error {
	return nil
}

func (f *fakeCommitter) Read(ctx context.Context, commitment []byte) (*tpb.Committed, error) {
	committed, ok := f.M[string(commitment)]
	if !ok {
		return nil, nil
	}
	return committed, nil
}

// tree.SparseHist fake.
type fakeSparseHist struct {
	M map[int64][]byte
}

func (*fakeSparseHist) QueueLeaf(txn transaction.Txn, index, leaf []byte) error     { return nil }
func (*fakeSparseHist) Commit(txn transaction.Txn) error                            { return nil }
func (*fakeSparseHist) ReadRootAt(txn transaction.Txn, epoch int64) ([]byte, error) { return nil, nil }
func (*fakeSparseHist) Epoch(txn transaction.Txn) (int64, error)                    { return 0, nil }
func (*fakeSparseHist) NeighborsAt(txn transaction.Txn, index []byte, epoch int64) ([][]byte, error) {
	return nil, nil
}

func (f *fakeSparseHist) ReadLeafAt(txn transaction.Txn, index []byte, epoch int64) ([]byte, error) {
	commitment, ok := f.M[epoch]
	if !ok {
		return nil, errors.New("not found")
	}
	entry := &tpb.Entry{Commitment: commitment}
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, errors.New("marshaling error")
	}
	return entryData, nil
}

// vrf.PrivateKey fake.
type fakePrivateKey struct{}

func (fakePrivateKey) Evaluate(m []byte) ([32]byte, []byte) { return [32]byte{}, nil }

func (fakePrivateKey) Public() ([]byte, error) { return []byte{}, nil }

// mutator.Mutator fake.
type fakeMutator struct{}

func (fakeMutator) CheckMutation(value, mutation []byte) error    { return nil }
func (fakeMutator) Mutate(value, mutation []byte) ([]byte, error) { return nil, nil }

// transaction.Txn fake
type fakeTxn struct{}

func (*fakeTxn) Prepare(query string) (*sql.Stmt, error) { return nil, nil }
func (*fakeTxn) Commit() error                           { return nil }
func (*fakeTxn) Rollback() error                         { return nil }

// transaction.Factory fake
type fakeFactory struct{}

func (fakeFactory) NewTxn(ctx context.Context) (transaction.Txn, error) {
	return &fakeTxn{}, nil
}

// mutator.Mutation fake
type fakeMutation struct{}

func (fakeMutation) ReadRange(txn transaction.Txn, startSequence, endSequence uint64, count int32) (uint64, []*tpb.SignedKV, error) {
	return 0, nil, nil
}

func (fakeMutation) ReadAll(txn transaction.Txn, startSequence uint64) (uint64, []*tpb.SignedKV, error) {
	return 0, nil, nil
}

func (fakeMutation) Write(txn transaction.Txn, mutation *tpb.SignedKV) (uint64, error) { return 0, nil }

// appender.Local
type fakeSequenced struct {
	l [][]byte
}

func (f *fakeSequenced) Write(txn transaction.Txn, logID int64, epoch int64, obj interface{}) error {
	var data bytes.Buffer
	if err := gob.NewEncoder(&data).Encode(obj); err != nil {
		return err
	}
	f.l = append(f.l, data.Bytes())
	return nil
}

func (f *fakeSequenced) Read(txn transaction.Txn, logID int64, epoch int64, obj interface{}) error {
	data := f.l[epoch]
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(obj)
}

func (f *fakeSequenced) Latest(txn transaction.Txn, logID int64, obj interface{}) (int64, error) {
	epoch := int64(len(f.l) - 1)
	err := f.Read(txn, logID, epoch, obj)
	return epoch, err
}

// authorization.Authorization fake
type fakeAuthz struct {
}

func (fakeAuthz) IsAuthorized(sctx *authentication.SecurityContext, mapID int64,
	appID, userID string, permission authzpb.Permission) error {
	return nil
}
