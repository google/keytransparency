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

package mutationstorage

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/impl/mysql/testdb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func newForTest(ctx context.Context, t testing.TB, dirID string, logIDs ...int64) *Mutations {
	db := testdb.NewForTest(ctx, t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutation storage: %v", err)
	}
	if err := m.AddLogs(ctx, dirID, logIDs...); err != nil {
		t.Fatalf("AddLogs(): %v", err)
	}
	return m
}

func TestMutationLogsIntegration(t *testing.T) {
	storagetest.RunMutationLogsTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) keyserver.MutationLogs {
			return newForTest(ctx, t, dirID, logIDs...)
		})
}

func TestLogsAdminIntegration(t *testing.T) {
	storagetest.RunLogsAdminTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) adminserver.LogsAdmin {
			return newForTest(ctx, t, dirID, logIDs...)
		})
}

func TestMutationLogsReaderIntegration(t *testing.T) {
	storagetest.RunMutationLogsReaderTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) storagetest.LogsReadWriter {
			return newForTest(ctx, t, dirID, logIDs...)
		})
}

func BenchmarkSendBatch(b *testing.B) {
	ctx := context.Background()
	directoryID := "BenchmarkSendBatch"
	logID := int64(1)
	m := newForTest(ctx, b, directoryID, logID)

	update := &pb.EntryUpdate{Mutation: &pb.SignedEntry{Entry: []byte("xxxxxxxxxxxxxxxxxx")}}
	for _, tc := range []struct {
		batch int
	}{
		{batch: 1},
		{batch: 2},
		{batch: 4},
		{batch: 8},
		{batch: 16},
		{batch: 32},
		{batch: 64},
		{batch: 128},
		{batch: 256},
	} {
		b.Run(fmt.Sprintf("%d", tc.batch), func(b *testing.B) {
			updates := make([]*pb.EntryUpdate, 0, tc.batch)
			for i := 0; i < tc.batch; i++ {
				updates = append(updates, update)
			}
			for n := 0; n < b.N; n++ {
				if _, err := m.SendBatch(ctx, directoryID, logID, updates); err != nil {
					b.Errorf("SendBatch(): %v", err)
				}
			}
		})
	}
}

func TestSendBatch(t *testing.T) {
	ctx := context.Background()

	directoryID := "TestSendBatch"
	m := newForTest(ctx, t, directoryID, 1, 2)
	update := []byte("bar")
	wm1 := water.NewMark(uint64(time.Duration(time.Now().UnixNano()) * time.Nanosecond / time.Microsecond))
	wm2 := wm1.Add(1000)
	wm3 := wm2.Add(1)

	// Test cases are cumulative. Earlier test caes setup later test cases.
	for _, tc := range []struct {
		desc     string
		wm       water.Mark
		wantCode codes.Code
	}{
		// Enforce watermark uniqueness.
		{desc: "First", wm: wm2},
		{desc: "Second", wm: wm2, wantCode: codes.Aborted},
		// Enforce a monotonically increasing watermark.
		{desc: "Old", wm: wm1, wantCode: codes.Aborted},
		{desc: "New", wm: wm3},
	} {
		err := m.send(ctx, tc.wm, directoryID, 1, update, update)
		if got, want := status.Code(err), tc.wantCode; got != want {
			t.Errorf("%v: send(): %v, got: %v, want %v", tc.desc, err, got, want)
		}
	}
}
