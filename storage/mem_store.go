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

	context "golang.org/x/net/context"
	keyspb "github.com/google/key-server-transparency/proto/v2"
)

// Storage holds state required to persist data. Open and Create create new Storage objects.
type MemStorage struct { 
	// Map of vuf -> SignedKey
	keys map[string]*keyspb.SignedKey
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{ }
	s.InsertLogTableRow(ctx)
	return s
}

func (s *MemStorage) InsertLogTableRow(ctx context.Context) { }

func (s *MemStorage) ReadKey(ctx context.Context, vuf []byte) (*keyspb.SignedKey, error) {
	val, ok := s.keys[string(vuf)]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	return val, nil
}
// UpdateKey updates a UserKey row. Fails if the row does not already exist.
func (s *MemStorage) UpdateKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error {
	_, ok := s.keys[string(vuf)]
	if !ok {
		return grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	s.keys[string(vuf)] = signedKey
	return nil
}
// InsertKey inserts a new UserKey row. Fails if the row already exists.
func (s *MemStorage) InsertKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error {
	_, ok := s.keys[string(vuf)]
	if ok {
		return grpc.Errorf(codes.AlreadyExists, "%v Already Exists", vuf)
	}
	s.keys[string(vuf)] = signedKey
	return nil
}
// DeleteKey deletes a key.
func (s *MemStorage) DeleteKey(ctx context.Context, vuf []byte) error {
	_, ok := s.keys[string(vuf)]
	if !ok {
		return grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	delete(s.keys, string(vuf))
	return nil
}

