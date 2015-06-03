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
	context "golang.org/x/net/context"
	keyspb "github.com/google/key-server-transparency/proto/v2"
)

// Storage holds state required to persist data. Open and Create create new Storage objects.
type MemStorage struct {
	logID []byte
}

// Open connects to a given version of the backend.
func OpenMem(ctx context.Context, logID []byte, universe, environment string) *MemStorage {
	// Database connection.
	return CreateMem(ctx, logID)
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context, logID []byte) *MemStorage {
	s := &MemStorage{
		logID: logID,
	}
	s.InsertLogTableRow(ctx)
	return s
}

func (s *MemStorage) InsertLogTableRow(ctx context.Context) {
}
// UpdateKey updates a UserKey row. Fails if the row does not already exist.
func (s *MemStorage) UpdateKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error {
return nil
}
// InsertKey inserts a new UserKey row. Fails if the row already exists.
func (s *MemStorage) InsertKey(ctx context.Context, signedKey *keyspb.SignedKey, vuf []byte) error {
return nil
}
// DeleteKey deletes a key.
func (s *MemStorage) DeleteKey(ctx context.Context, vuf []byte) error {
return nil
}
// ReadKey reads a key.
func (s *MemStorage) ReadKey(ctx context.Context, vuf []byte) (*keyspb.SignedKey, error) {
return nil, nil
}

