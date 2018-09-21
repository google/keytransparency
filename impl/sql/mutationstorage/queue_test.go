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
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	_ "github.com/mattn/go-sqlite3"
)

func TestSend(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}
	domainID := "foo"
	update := []byte("bar")
	ts1 := time.Now()
	ts2 := ts1.Add(time.Duration(1))
	ts3 := ts2.Add(time.Duration(1))

	if err := m.AddShards(ctx, domainID, 1, 2); err != nil {
		t.Fatalf("AddShards(): %v", err)
	}

	// Test cases are cumulative. Earlier test caes setup later test cases.
	for _, tc := range []struct {
		desc     string
		ts       time.Time
		wantCode codes.Code
	}{
		// Enforce timestamp uniqueness.
		{desc: "First", ts: ts2},
		{desc: "Second", ts: ts2, wantCode: codes.Aborted},
		// Enforce a monotonically increasing timestamp
		{desc: "Old", ts: ts1, wantCode: codes.Aborted},
		{desc: "New", ts: ts3},
	} {
		err := m.send(ctx, domainID, 1, update, tc.ts)
		if got, want := status.Code(err), tc.wantCode; got != want {
			t.Errorf("%v: send(): %v, got: %v, want %v", tc.desc, err, got, want)
		}
	}
}

func TestWatermark(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create Mutations: %v", err)
	}
	domainID := "foo"
	ts1 := time.Now()
	ts2 := ts1.Add(time.Duration(1))

	if err := m.AddShards(ctx, domainID, 1, 2); err != nil {
		t.Fatalf("AddShards(): %v", err)
	}

	for _, tc := range []struct {
		desc string
		send bool
		ts   time.Time
		want int64
	}{
		{desc: "no rows", want: 0},
		{desc: "first", send: true, ts: ts1, want: ts1.UnixNano()},
		{desc: "second", send: true, ts: ts2, want: ts2.UnixNano()},
	} {
		if tc.send {
			if err := m.send(ctx, domainID, 1, []byte("foo"), tc.ts); err != nil {
				t.Fatalf("send(): %v", err)
			}
		}
		high, err := m.HighWatermark(ctx, domainID)
		if err != nil {
			t.Fatalf("HighWatermark(): %v", err)
		}
		if high != tc.want {
			t.Errorf("HighWatermark(): %v, want > %v", high, tc.want)
		}
	}
}
