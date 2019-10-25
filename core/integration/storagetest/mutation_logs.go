// Copyright 2019 Google Inc. All Rights Reserved.
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

package storagetest

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/keyserver"
	"golang.org/x/sync/errgroup"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// mutationLogsFactory returns a new database object, and a function for cleaning it up.
type mutationLogsFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) (keyserver.MutationLogs, func(context.Context))

// RunMutationLogsTests runs all the tests against the provided storage implementation.
func RunMutationLogsTests(t *testing.T, factory mutationLogsFactory) {
	ctx := context.Background()
	b := &mutationLogsTests{}
	for name, f := range map[string]func(ctx context.Context, t *testing.T, f mutationLogsFactory){
		// TODO(gbelvin): Discover test methods via reflection.
		"TestReadLog": b.TestReadLog,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

type mutationLogsTests struct{}

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(): %v", err)
	}
	return b
}

// TestReadLog ensures that reads happen in atomic units of batch size.
func (mutationLogsTests) TestReadLog(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestReadLog"
	logID := int64(5) // Any log ID.
	m, done := newForTest(ctx, t, directoryID, logID)
	defer done(ctx)
	// Write ten batches, three entries each.
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		if _, err := m.Send(ctx, directoryID, entry, entry, entry); err != nil {
			t.Fatalf("Send(): %v", err)
		}
	}

	for _, tc := range []struct {
		limit int32
		want  int
	}{
		{limit: 0, want: 0},
		{limit: 1, want: 3},    // We asked for 1 item, which gets us into the first batch, so we return 3 items.
		{limit: 3, want: 3},    // We asked for 3 items, which gets us through the first batch, so we return 3 items.
		{limit: 4, want: 6},    // Reading 4 items gets us into the second batch of size 3.
		{limit: 100, want: 30}, // Reading all the items gets us the 30 items we wrote.
	} {
		rows, err := m.ReadLog(ctx, directoryID, logID, time.Time{}, time.Now(), tc.limit)
		if err != nil {
			t.Fatalf("ReadLog(%v): %v", tc.limit, err)
		}
		if got := len(rows); got != tc.want {
			t.Fatalf("ReadLog(%v): len: %v, want %v", tc.limit, got, tc.want)
		}
	}
}

func (mutationLogsTests) TestConcurrentWrites(ctx context.Context, t *testing.T, newForTest mutationLogsFactory) {
	directoryID := "TestConcurrentWrites"
	logID := int64(5)
	m, done := newForTest(ctx, t, directoryID, logID)
	defer done(ctx)
	for i, concurrency := range []int{1, 2, 4, 8, 16, 32, 64} {
		var g errgroup.Group
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{byte(i)}})}}
		for i := 0; i < concurrency; i++ {
			g.Go(func() error {
				_, err := m.Send(ctx, directoryID, entry)
				return err
			})
		}
		if err := g.Wait(); err != nil {
			t.Errorf("concurrency: %d, err: %v", concurrency, err)
		}
	}
}
