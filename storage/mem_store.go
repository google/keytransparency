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

const (
	// This is the buffer size of the channel used to send an EntryStorage
	// to the tree builder.
	CHANNEL_SIZE = 100
)

// Storage holds state required to persist data. Open and Create create new
// Storage objects.
type MemStorage struct {
	// Map of vuf -> EntryStorage
	entries map[string]*internalpb.EntryStorage
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into ch.
	ch chan interface{}
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries: make(map[string]*internalpb.EntryStorage),
		ch:      make(chan interface{}, CHANNEL_SIZE),
	}
	return s
}

// Read reads a EntryStroage from the storage.
func (s *MemStorage) Read(ctx context.Context, vuf string) (*internalpb.EntryStorage, error) {
	val, ok := s.entries[string(vuf)]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", vuf)
	}
	return val, nil
}

// Write inserts a new EntryStorage in the storage. This function works whether
// the entry exists or not. If the entry does not exist, it will be inserted,
// otherwise updated.
func (s *MemStorage) Write(ctx context.Context, entry *internalpb.EntryStorage, vuf string) error {
	s.entries[string(vuf)] = entry
	// Push entry in the channel in order to be added to the merkle tree.
	s.ch <- entry
	return nil
}

func (s *MemStorage) GetChannel() chan interface{} {
	return s.ch
}

func (s *MemStorage) CloseChannel() {
	close(s.ch)
}
