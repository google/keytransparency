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

	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func TestWatermark(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	domainID := "foo"

	_, err = m.HighWatermark(ctx, domainID)
	if got, want := status.Code(err), codes.NotFound; got != want {
		t.Errorf("HighWatermark(): %v, want %v", got, want)
	}

	if err := m.Send(ctx, domainID, &pb.EntryUpdate{}); err != nil {
		t.Fatalf("Send(): %v", err)
	}
	high1, err := m.HighWatermark(ctx, domainID)
	if got, want := status.Code(err), codes.OK; got != want {
		t.Errorf("HighWatermark(): %v, want %v", got, want)
	}
	if got, want := high1, int64(1); got < want {
		t.Errorf("HighWatermark(): %v, want > %v", got, want)
	}
	if err := m.Send(ctx, domainID, &pb.EntryUpdate{}); err != nil {
		t.Fatalf("Send(): %v", err)
	}
	high2, err := m.HighWatermark(ctx, domainID)
	if got, want := status.Code(err), codes.OK; got != want {
		t.Errorf("HighWatermark(): %v, want %v", got, want)
	}
	if high2 <= high1 {
		t.Errorf("HighWatermark(): %v, want > %v", high2, high1)
	}
}
