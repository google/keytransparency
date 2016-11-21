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
	"database/sql"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/key-transparency/core/authentication"
	"github.com/google/key-transparency/core/queue"
	"github.com/google/key-transparency/core/transaction"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
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
		{1, 10, 11, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, codes.OK},                              // 10 entries per page.
		{4, 10, 14, []int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, codes.OK},                           // start epoch is not 1.
		{1, 0, 17, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, codes.OK},       // zero page size.
		{20, 10, 0, []int{20, 21, 22, 23, 24}, codes.OK},                                         // end of list.
		{24, 10, 0, []int{24}, codes.OK},                                                         // requesting the very last entry.
		{1, 1000000, 17, []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, codes.OK}, // DOS prevention.
		{40, 10, 0, []int{}, codes.InvalidArgument},                                              // start epoch is beyond current epoch.
		{0, 1, 1, []int{0}, codes.OK},                                                            // start epoch is less than 1.
	} {
		// Test case setup.
		c := &fakeCommitter{make(map[string]*tpb.Committed)}
		st := &fakeSparseHist{make(map[int64][]byte)}
		a := &fakeAppender{0, 0}
		srv := New(c, fakeQueue{}, st, a, fakePrivateKey{}, fakeMutator{}, authentication.NewFake(), fakeFactory{})
		if err := addProfiles(profileCount, c, st, a); err != nil {
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
			t.Errorf("%v: ListEntryHistory(_, %v)=(_, %v), want %v", i, req, err, tc.err)
		}
		// Skip the rest of the test if there is an error.
		if err != nil {
			continue
		}

		// Check next epoch.
		if got, want := resp.NextStart, tc.wantNext; got != want {
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
			t.Errorf("%v: checkProfiles failed: %v, want nil", i, got)
		}

		// Verify mocks.
		// Ensure that latest is called only once.
		if got, want := a.LatestCount, 1; got != want {
			t.Errorf("%v: Incorrect number of Latest() call(s), got %v, want %v", i, got, want)
		}
	}
}

func addProfiles(count int, c *fakeCommitter, st *fakeSparseHist, a *fakeAppender) error {
	profiles := make([]*tpb.Profile, count)
	for i := range profiles {
		profiles[i] = createProfile(i)
		commitment := []byte{uint8(i)}

		// Fill the committer map.
		pData, err := proto.Marshal(profiles[i])
		if err != nil {
			return fmt.Errorf("%v: Failed to Marshal: %v", i, err)
		}
		committed := &tpb.Committed{Data: pData}
		c.M[string(commitment)] = committed
		st.M[int64(i)] = commitment
		a.CurrentEpoch = int64(i)
	}
	return nil
}

// checkProfiles Ensure that the history has the correct entries in the correct
// order.
func checkProfiles(wantHistory []int, values []*tpb.GetEntryResponse) error {
	for i, tag := range wantHistory {
		p := new(tpb.Profile)
		if err := proto.Unmarshal(values[i].Committed.Data, p); err != nil {
			return fmt.Errorf("%v: Failed to Unmarshal: %v", i, err)
		}
		if got, want := p, createProfile(tag); !reflect.DeepEqual(got, want) {
			return fmt.Errorf("%v: Invalid profile: %v, want %v", i, got, want)
		}
	}
	return nil
}

// createProfile creates a dummy profile using the passed tag.
func createProfile(tag int) *tpb.Profile {
	return &tpb.Profile{
		Keys: map[string][]byte{
			fmt.Sprintf("foo%v", tag): []byte(fmt.Sprintf("bar%v", tag)),
		},
	}
}

///////////
// Fakes //
///////////

// commitments.Committer fake.
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

// queue.Queuer fake.
type fakeQueue struct {
}

func (fakeQueue) Enqueue(key, value []byte) error {
	return nil
}

func (fakeQueue) AdvanceEpoch() error {
	return nil
}

func (fakeQueue) StartReceiving(_ queue.ProcessKeyValueFunc, _ queue.AdvanceEpochFunc) (queue.Receiver, error) {
	return nil, nil
}

// tree.SparseHist fake.
type fakeSparseHist struct {
	M map[int64][]byte
}

func (*fakeSparseHist) QueueLeaf(txn transaction.Txn, index, leaf []byte) error {
	return nil
}

func (*fakeSparseHist) Commit(ctx context.Context) (epoch int64, err error) {
	return 0, nil
}

func (*fakeSparseHist) ReadRootAt(txn transaction.Txn, epoch int64) ([]byte, error) {
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

func (*fakeSparseHist) NeighborsAt(ctx context.Context, index []byte, epoch int64) ([][]byte, error) {
	return nil, nil
}

func (*fakeSparseHist) Epoch() int64 {
	return 0
}

// appender.Appender fake.
type fakeAppender struct {
	CurrentEpoch int64
	LatestCount  int
}

func (*fakeAppender) Append(ctx context.Context, txn transaction.Txn, epoch int64, obj interface{}) error {
	return nil
}

func (*fakeAppender) Epoch(ctx context.Context, epoch int64, obj interface{}) ([]byte, error) {
	return nil, nil
}

func (f *fakeAppender) Latest(ctx context.Context, obj interface{}) (int64, []byte, error) {
	f.LatestCount++
	return f.CurrentEpoch, nil, nil
}

// vrf.PrivateKey fake.
type fakePrivateKey struct {
}

func (fakePrivateKey) Evaluate(m []byte) (vrf []byte, proof []byte) {
	return nil, nil
}

func (fakePrivateKey) Index(vrf []byte) [32]byte {
	return [32]byte{}
}

// mutator.Mutator fake.
type fakeMutator struct {
}

func (fakeMutator) CheckMutation(value, mutation []byte) error {
	return nil
}

func (fakeMutator) Mutate(value, mutation []byte) ([]byte, error) {
	return nil, nil
}

// transaction.Txn fake
type fakeTxn struct {
}

func (*fakeTxn) Prepare(query string) (*sql.Stmt, error) { return nil, nil }
func (*fakeTxn) Commit() error                           { return nil }
func (*fakeTxn) Rollback() error                         { return nil }

// transaction.Factory fake
type fakeFactory struct {
}

func (fakeFactory) NewDBTxn(ctx context.Context) (transaction.Txn, error) {
	return &fakeTxn{}, nil
}
