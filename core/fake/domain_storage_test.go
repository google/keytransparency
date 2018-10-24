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

package fake

import (
	"context"
	"testing"

	"github.com/google/keytransparency/core/directory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestDelete(t *testing.T) {
	s := NewDirectoryStorage()
	ctx := context.Background()
	for _, tc := range []struct {
		directoryID string
	}{
		{directoryID: "test"},
		{directoryID: ""},
	} {
		d := &directory.Directory{DirectoryID: tc.directoryID}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.Delete(ctx, tc.directoryID); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, tc.directoryID, true)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
		_, err = s.Read(ctx, tc.directoryID, false)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
	}
}

func TestSetDelete(t *testing.T) {
	s := NewDirectoryStorage()
	ctx := context.Background()
	for _, tc := range []struct {
		directoryID string
	}{
		{directoryID: "test"},
	} {
		d := &directory.Directory{DirectoryID: tc.directoryID}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.SetDelete(ctx, tc.directoryID, true); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, tc.directoryID, false)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
		if _, err := s.Read(ctx, tc.directoryID, true); err != nil {
			t.Errorf("Read(): %v", err)
		}
	}
}

func TestList(t *testing.T) {
	s := NewDirectoryStorage()
	ctx := context.Background()
	directories := []*directory.Directory{
		{DirectoryID: "test1"},
		{DirectoryID: "test2", Deleted: true},
		{DirectoryID: "test3"},
	}
	for _, d := range directories {
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.SetDelete(ctx, d.DirectoryID, d.Deleted); err != nil {
			t.Errorf("SetDelete(): %v", err)
		}
	}
	ret, err := s.List(ctx, false)
	if err != nil {
		t.Errorf("List()): %v", err)
	}
	directorySet := make(map[string]bool)
	for _, d := range ret {
		directorySet[d.DirectoryID] = true
	}
	for _, d := range directories {
		if !d.Deleted && !directorySet[d.DirectoryID] {
			t.Errorf("Didn't find directory %v in output", d.DirectoryID)
		}
	}
}
