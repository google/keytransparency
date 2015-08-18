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

	corepb "github.com/google/e2e-key-server/proto/core"
	context "golang.org/x/net/context"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

// Storage holds state required to persist data. Open and Create create new
// Storage objects.
type MemStorage struct {
	// Map of index -> EntryStorage
	entries map[string]*corepb.EntryStorage
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into ch.
	ch chan *corepb.EntryStorage
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries: make(map[string]*corepb.EntryStorage),
		ch:      make(chan *corepb.EntryStorage, ChannelSize),
	}
	return s
}

// Read reads a EntryStroage from the storage.
func (s *MemStorage) Read(ctx context.Context, index string) (*corepb.EntryStorage, error) {
	val, ok := s.entries[string(index)]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", index)
	}
	return val, nil
}

// Write inserts a new EntryStorage in the storage. This function works whether
// the entry exists or not. If the entry does not exist, it will be inserted,
// otherwise updated.
func (s *MemStorage) Write(ctx context.Context, entry *corepb.EntryStorage, index string) error {
	s.entries[string(index)] = entry
	// Push entry in the channel in order to be added to the merkle tree.
	s.ch <- entry
	return nil
}

// NewEntries  returns a channel containing EntryStorage entries, which are
// pushed into the channel whenever an EntryStorage is written in the stirage.
func (s *MemStorage) NewEntries() chan *corepb.EntryStorage {
	return s.ch
}
