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

	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func TestSend(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	domainID := "foo"
	update := &pb.EntryUpdate{}

	for _, tc := range []struct {
		desc     string
		ts       time.Time
		wantCode codes.Code
	}{
		{desc: "First"},
		{desc: "Second", wantCode: codes.Aborted},
	} {
		err := m.send(ctx, domainID, update, tc.ts)
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
		t.Fatalf("Failed to create mutations: %v", err)
	}
	domainID := "foo"

	for _, tc := range []struct {
		desc string
		send bool
		want int64
	}{
		{desc: "no rows", want: 0},
		{desc: "first", send: true, want: time.Now().UnixNano()},
		{desc: "second", send: true, want: time.Now().UnixNano()},
	} {
		if tc.send {
			if err := m.Send(ctx, domainID, &pb.EntryUpdate{}); err != nil {
				t.Fatalf("Send(): %v", err)
			}
		}
		high, err := m.HighWatermark(ctx, domainID)
		if err != nil {
			t.Fatalf("HighWatermark(): %v", err)
		}
		if high < tc.want {
			t.Errorf("HighWatermark(): %v, want > %v", high, tc.want)
		}
	}
}
