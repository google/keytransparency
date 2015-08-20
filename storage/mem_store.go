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
	"fmt"

	"github.com/google/e2e-key-server/common"
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
	startCommitmentTs common.CommitmentTimestamp
	endCommitmentTs   common.CommitmentTimestamp
}

// Storage holds state required to persist data. Open and Create create new
// Storage objects.
type MemStorage struct {
	// Map of commitment timestamp -> EntryStorage.
	entries map[common.CommitmentTimestamp]*corepb.EntryStorage
	// Map of epoch -> start and end commitment timestamp range.
	epochs map[common.Epoch]epochInfo
	// Map of (index, epoch) -> commitment timestamp. The key is a string
	// concatenation of both index and epoch. Eventually, this map will be
	// a database table keyed by index and epoch.
	indices map[string]common.CommitmentTimestamp
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into ch.
	ch chan *corepb.EntryStorage
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries: make(map[common.CommitmentTimestamp]*corepb.EntryStorage),
		epochs:  make(map[common.Epoch]epochInfo),
		indices: make(map[string]common.CommitmentTimestamp),
		ch:      make(chan *corepb.EntryStorage, ChannelSize),
	}
	return s
}

// Read reads a EntryStroage from the storage. index is in hex format.
func (s *MemStorage) Read(ctx context.Context, index string, epoch common.Epoch) (*corepb.EntryStorage, error) {
	commitmentTs, ok := s.indices[fmt.Sprintf("%v%v", index, epoch)]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", commitmentTs)
	}

	val := s.entries[commitmentTs]
	return val, nil
}

// Write inserts a new EntryStorage in the storage. This function works whether
// the entry exists or not. If the entry does not exist, it will be inserted,
// otherwise updated.
func (s *MemStorage) Write(ctx context.Context, entry *corepb.EntryStorage) error {
	// Get the current commitment timestamp and use it when writing the
	// entry.
	commitmentTs := GetCurrentCommitmentTimestamp()
	entry.CommitmentTimestamp = uint64(commitmentTs)
	// Write the entry.
	s.entries[commitmentTs] = entry
	// Push entry in the channel in order to be added to the merkle tree.
	s.ch <- entry
	return nil
}

// WriteEntryRelatedInfo stores the mapping of epoch -> commitment timestamp
// range and (index, epoch) -> commitment timestamp. index is in hex format.
func (s *MemStorage) WriteEntryRelatedInfo(index string, epoch common.Epoch, commitmentTs common.CommitmentTimestamp) error {
	// Write epoch -> commitment timestamp range mapping.
	eInfo, ok := s.epochs[epoch]
	if ok {
		eInfo.endCommitmentTs = commitmentTs
	} else {
		// If the entry doesn't exist, set both start and end commitment
		// timestamps to be equal to commitmentTs. In this case, there's
		// only one commitment timestamp in this epoch.
		eInfo = epochInfo{commitmentTs, commitmentTs}
	}
	s.epochs[epoch] = eInfo

	// Write (index, epoch) -> commitment timestamp mapping. It is ok if
	// (index, epoch) key exists, this can happen in case of multiple
	// updates of the same profile in the same epoch.
	s.indices[fmt.Sprintf("%v%v", index, epoch)] = commitmentTs

	return nil
}

// NewEntries  returns a channel containing EntryStorage entries, which are
// pushed into the channel whenever an EntryStorage is written in the stirage.
func (s *MemStorage) NewEntries() chan *corepb.EntryStorage {
	return s.ch
}
