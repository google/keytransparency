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
)

type epochInfo struct {
	startCommitmentTS uint64
	endCommitmentTS   uint64
}

// MemStorage holds state required to store data in memory. CreateMem creates a
// new MemStorage objects.
type MemStorage struct {
	// Map of commitment timestamp -> EntryStorage.
	entries map[uint64]*corepb.EntryStorage
	// Map of epoch -> start and end commitment timestamp range.
	// TODO(cesarghali): this map is not yet used. Use it when epochs
	//                   are created.
	epochs map[uint64]epochInfo
	// Whenever an EntryStorage is written in MemStorage, it will be pushed
	// into these channels.
	outChan []chan *corepb.EntryStorage
}

// Create creates a storage object from an existing db connection.
func CreateMem(outChan []chan *corepb.EntryStorage) *MemStorage {
	return &MemStorage{
		entries: make(map[uint64]*corepb.EntryStorage),
		epochs:  make(map[uint64]epochInfo),
		outChan: outChan,
	}
}

// Read reads a EntryStroage from the storage.
func (s *MemStorage) Read(commitmentTS uint64) (*corepb.EntryStorage, error) {
	val, ok := s.entries[commitmentTS]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", commitmentTS)
	}

	return val, nil
}

// Write inserts a new EntryStorage in the storage. This function works whether
// the entry exists or not. If the entry does not exist, it will be inserted,
// otherwise updated.
func (s *MemStorage) Write(entry *corepb.EntryStorage) error {
	// Get the current commitment timestamp and use it when writing the
	// entry.
	commitmentTS := GetCurrentCommitmentTimestamp()
	entry.CommitmentTimestamp = uint64(commitmentTS)
	// Write the entry.
	s.entries[commitmentTS] = entry
	// Push entry into the outgoing channels.
	for _, ch := range s.outChan {
		if ch != nil {
			ch <- entry
		}
	}
	return nil
}
