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

	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/adminserver"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type QueueAdminFactory func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) adminserver.LogsAdmin

type QueueAdminTest func(ctx context.Context, t *testing.T, f QueueAdminFactory)

// RunQueueAdminTests runs all the queue admin tests against the provided storage implementation.
func RunQueueAdminTests(t *testing.T, factory QueueAdminFactory) {
	ctx := context.Background()
	b := &QueueAdminTests{}
	for name, f := range map[string]QueueAdminTest{
		// TODO(gbelvin): Discover test methods via reflection.
		"TestSetWritable": b.TestSetWritable,
	} {
		t.Run(name, func(t *testing.T) { f(ctx, t, factory) })
	}
}

// QueueTests is a suite of tests to run against
type QueueAdminTests struct{}

func (QueueAdminTests) TestSetWritable(ctx context.Context, t *testing.T, f QueueAdminFactory) {
	directoryID := "TestSetWritable"
	for _, tc := range []struct {
		desc       string
		logIDs     []int64
		set        map[int64]bool
		wantLogIDs []int64
		wantCode   codes.Code
	}{
		{desc: "one row", logIDs: []int64{10}, wantLogIDs: []int64{10}},
		{desc: "one row disabled", logIDs: []int64{10}, set: map[int64]bool{10: false}, wantCode: codes.NotFound},
		{desc: "one row enabled", logIDs: []int64{1, 2, 3}, set: map[int64]bool{1: false, 2: false}, wantLogIDs: []int64{3}},
		{desc: "multi", logIDs: []int64{1, 2, 3}, set: map[int64]bool{1: true, 2: false}, wantLogIDs: []int64{1, 3}},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			m := f(ctx, t, directoryID, tc.logIDs...)
			wantLogs := make(map[int64]bool)
			for _, logID := range tc.wantLogIDs {
				wantLogs[logID] = true
			}

			for logID, enabled := range tc.set {
				if err := m.SetWritable(ctx, directoryID, logID, enabled); err != nil {
					t.Errorf("SetWritable(): %v", err)
				}
			}

			logIDs, err := m.ListLogs(ctx, directoryID, true /* Only Writable */)
			if status.Code(err) != tc.wantCode {
				t.Errorf("ListLogs(): %v, want %v", err, tc.wantCode)
			}
			if err != nil {
				return
			}
			logs := make(map[int64]bool)
			for _, log := range logIDs {
				logs[log] = true
			}
			if got, want := logs, wantLogs; !cmp.Equal(got, want) {
				t.Errorf("randLog(): %v, want %v", got, want)
			}
		})
	}
}
