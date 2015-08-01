// Copyright 2015 Google Inc. All Rights Reserved.
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
// Package proxy converts v1 API requests into v2 API calls.

package storage

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	internalpb "github.com/google/e2e-key-server/proto/internal"
	context "golang.org/x/net/context"
)

// Storage holds state required to persist data. Open and Create create new
// Storage objects.
type MemStorage struct {
	// Map of vuf -> EntryStorage
	profiles map[string]*internalpb.EntryStorage
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{make(map[string]*internalpb.EntryStorage)}
	s.InsertLogTableRow(ctx)
	return s
}

func (s *MemStorage) InsertLogTableRow(ctx context.Context) {}

func (s *MemStorage) ReadEntryStorage(ctx context.Context, vuf string) (*internalpb.EntryStorage, error) {
	val, ok := s.profiles[string(vuf)]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	return val, nil
}

// UpdateEntryStorage updates a UserEntryStorage row. Fails if the row does not
// already exist.
func (s *MemStorage) UpdateEntryStorage(ctx context.Context, profile *internalpb.EntryStorage, vuf string) error {
	_, ok := s.profiles[string(vuf)]
	if !ok {
		return grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	s.profiles[string(vuf)] = profile
	return nil
}

// InsertEntryStorage inserts a new UserEntryStorage row. Fails if the row
// already exists.
func (s *MemStorage) InsertEntryStorage(ctx context.Context, profile *internalpb.EntryStorage, vuf string) error {
	_, ok := s.profiles[string(vuf)]
	if ok {
		return grpc.Errorf(codes.AlreadyExists, "%v Already Exists", vuf)
	}
	s.profiles[string(vuf)] = profile
	return nil
}

// DeleteEntryStorage deletes a profile.
func (s *MemStorage) DeleteEntryStorage(ctx context.Context, vuf string) error {
	_, ok := s.profiles[string(vuf)]
	if !ok {
		return grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	delete(s.profiles, string(vuf))
	return nil
}

// EntryStorageExists returns true if an entry already exists for the given VUF,
// and false otherwise.
func (s *MemStorage) EntryStorageExists(ctx context.Context, vuf string) bool {
	_, ok := s.profiles[string(vuf)]
	return ok
}
