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
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	context "golang.org/x/net/context"
)

// Storage holds state required to persist data. Create creates new Storage
// objects.
type MemStorage struct {
	// Map of commitment timestamp -> EntryStorage.
	entries map[uint64]*corepb.EntryStorage
	// Map of epoch -> start and end commitment timestamp range.
	// TODO(cesarghali): this map is not yet used. Use it when epochs
	//                   are created.
	epochs map[uint64]*corepb.EpochInfo
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into builderUpdates.
	builderUpdates chan *corepb.EntryStorage
	// Whenever an EntryStorage is written in the database, it will be
	// pushed into signerUpdates.
	signerUpdates chan *corepb.EntryStorage
	// Whenever WriteEpochInfo is called, the EpochInfo object being written
	// in the storage is pushed into epochInfo.
	epochInfo chan *corepb.EpochInfo
	// Contains the timestamp of the last update to be included in the new
	// epoch.
	lastCommitmentTS uint64
	// mu synchronizes access to lastCommitmentTS
	mu sync.Mutex
}

// Create creates a storage object from an existing db connection.
func CreateMem(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries:        make(map[uint64]*corepb.EntryStorage),
		epochs:         make(map[uint64]*corepb.EpochInfo),
		builderUpdates: make(chan *corepb.EntryStorage, ChannelSize),
		signerUpdates:  make(chan *corepb.EntryStorage, ChannelSize),
		epochInfo:      make(chan *corepb.EpochInfo, ChannelSize),
	}
	return s
}

// ReadUpdate reads a EntryStroage from the storage.
func (s *MemStorage) ReadUpdate(ctx context.Context, commitmentTS uint64) (*corepb.EntryStorage, error) {
	val, ok := s.entries[commitmentTS]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", commitmentTS)
	}

	return val, nil
}

// WriteUpdate inserts a new EntryStorage in the storage. This function works
// whether the entry exists or not. If the entry does not exist, it will be
// inserted, otherwise updated.
func (s *MemStorage) WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error {
	// Get the current commitment timestamp and use it when writing the
	// entry.
	commitmentTS := GetCurrentCommitmentTimestamp()
	entry.CommitmentTimestamp = uint64(commitmentTS)
	// Write the entry.
	s.entries[commitmentTS] = entry

	s.mu.Lock()
	s.lastCommitmentTS = commitmentTS
	s.mu.Unlock()

	// Push entry in the channel in order to be added to the merkle tree.
	s.builderUpdates <- entry
	s.signerUpdates <- entry
	return nil
}

// WriteEpochInfo writes the epoch information in the storage.
func (s *MemStorage) WriteEpochInfo(ctx context.Context, epoch uint64, info *corepb.EpochInfo) error {
	s.epochs[epoch] = info
	s.epochInfo <- info
	// TODO(cesarghali): write signed epoch head to local storage.
	// Advance epoch
	return nil
}

// BuilderUpdates returns a channel containing EntryStorage entries, which are
// pushed into the channel whenever an EntryStorage is written in the storage.
// This channel is watched by the builder.
func (s *MemStorage) BuilderUpdates() chan *corepb.EntryStorage {
	return s.builderUpdates
}

// SignerUpdates returns a channel containing EntryStorage entries, which are
// pushed into the channel whenever an EntryStorage is written in the storage.
// This channel is watched by the signer.
func (s *MemStorage) SignerUpdates() chan *corepb.EntryStorage {
	return s.signerUpdates
}

// EpochInfo returns a channel that is used to transmit EpochInfo to the builder
// once the signer creates a new epoch.
func (s *MemStorage) EpochInfo() chan *corepb.EpochInfo {
	return s.epochInfo
}

// LastCommitmentTimestamp returns the timestamp of the last update that should
// included in the new epoch.
func (s *MemStorage) LastCommitmentTimestamp() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastCommitmentTS
}
