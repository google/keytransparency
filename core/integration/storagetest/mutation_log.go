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

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

type QueueStorageFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) keyserver.MutationLogs

type QueueStorageTest func(ctx context.Context, t *testing.T, f QueueStorageFactory)

// RunQueueStorageTests runs all the queue tests against the provided storage implementation.
func RunQueueStorageTests(t *testing.T, factory QueueStorageFactory) {
	ctx := context.Background()
	b := &QueueTests{}
	for name, f := range map[string]QueueStorageTest{
		// TODO(gbelvin): Discover test methods via reflection.
		"TestReadLog": b.TestReadLog,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

// QueueTests is a suite of tests to run against
type QueueTests struct{}

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	b, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(): %v", err)
	}
	return b
}

func (QueueTests) TestReadLog(ctx context.Context, t *testing.T, newForTest QueueStorageFactory) {
	directoryID := "TestReadLog"
	logID := int64(5)
	m := newForTest(ctx, t, directoryID, logID)
	for i := byte(0); i < 10; i++ {
		entry := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: mustMarshal(t, &pb.Entry{Index: []byte{i}})}}
		if _, err := m.Send(ctx, directoryID, entry, entry, entry); err != nil {
			t.Fatalf("Send(): %v", err)
		}
	}

	for _, tc := range []struct {
		batchSize int32
		count     int
	}{
		{batchSize: 0, count: 0},
		{batchSize: 1, count: 3},
		{batchSize: 4, count: 6},
		{batchSize: 100, count: 30},
	} {
		rows, err := m.ReadLog(ctx, directoryID, logID, 0, time.Now().UnixNano(), tc.batchSize)
		if err != nil {
			t.Fatalf("ReadLog(%v): %v", tc.batchSize, err)
		}
		if got, want := len(rows), tc.count; got != want {
			t.Fatalf("ReadLog(%v): len: %v, want %v", tc.batchSize, got, want)
		}
	}
}
