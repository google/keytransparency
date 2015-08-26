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

type epochInfo struct {
	startCommitmentTS uint64
	endCommitmentTS   uint64
}

// Storage holds state required to persist data. Open and Create create new
// Storage objects.
type MemStorage struct {
	// Map of commitment timestamp -> EntryStorage.
	entries map[uint64]*corepb.EntryStorage
	// Map of epoch -> start and end commitment timestamp range.
	// TODO(cesarghali): this map is not yet used. Use it when epochs
	//                   are created.
	epochs map[uint64]epochInfo
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into ch.
	ch chan *corepb.EntryStorage
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries: make(map[uint64]*corepb.EntryStorage),
		epochs:  make(map[uint64]epochInfo),
		ch:      make(chan *corepb.EntryStorage, ChannelSize),
	}
	return s
}

// Read reads a EntryStroage from the storage.
func (s *MemStorage) Read(ctx context.Context, commitmentTS uint64) (*corepb.EntryStorage, error) {
	val, ok := s.entries[commitmentTS]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", commitmentTS)
	}

	return val, nil
}

// ReadRange returns the specified size of EntryStroages list starting by the
// specified commitment timestamp.
func (s *MemStorage) ReadRange(ctx context.Context, startCommitmentTS uint64, size int32) ([]*corepb.EntryStorage, error) {
	// In a real database this function will be implemented by querying the
	// database, e.g. using SQL, for all storage entries starting with
	// startCommitmentTS. Since MemStorage uses a map, the only way to
	// simulate this is by looping over all entries in the map and extract
	// the relevant ones.

	keys := make([]uint64, len(s.entries))
	i := 0
	for k, _ := range(s.entries) {
		keys[i] = k
		i++
	}
	// Golang sort package doesn't have function to sort uint64, so the sort
	// is implemented.
	sortUint64(keys)

	result := make([]*corepb.EntryStorage, 0, size)
	for _, ts := range(keys) {
		if ts >= startCommitmentTS {
			result = append(result, s.entries[ts])
		}
		// Stop if size is reached
		if size != 0 && int32(len(result)) == size {
			break
		}
	}
	return result, nil
}

// sortUint64 is used by ReadRange and it bubble sorts a uint64 slice. This
// sorting is temporary so no need for an efficient one. Eventually, ReadRange
// will query the database to return entries sorted by commitment timestamp.
func sortUint64(a []uint64) {
	for i := 0; i < len(a) - 1; i++ {
		for j := i + 1; j < len(a); j++ {
			if a[j] < a[i] {
				t := a[i]
				a[i] = a[j]
				a[j] = t
			}
		}
	}
}

// Write inserts a new EntryStorage in the storage. This function works whether
// the entry exists or not. If the entry does not exist, it will be inserted,
// otherwise updated.
func (s *MemStorage) Write(ctx context.Context, entry *corepb.EntryStorage) error {
	// Get the current commitment timestamp and use it when writing the
	// entry.
	commitmentTS := GetCurrentCommitmentTimestamp()
	entry.CommitmentTimestamp = uint64(commitmentTS)
	// Write the entry.
	s.entries[commitmentTS] = entry
	// Push entry in the channel in order to be added to the merkle tree.
	s.ch <- entry
	return nil
}

// NewEntries  returns a channel containing EntryStorage entries, which are
// pushed into the channel whenever an EntryStorage is written in the stirage.
func (s *MemStorage) NewEntries() chan *corepb.EntryStorage {
	return s.ch
}
