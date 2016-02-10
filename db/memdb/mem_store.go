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

package memdb

import (
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_core"
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
	// pushed into all updates channels.
	updates []chan *corepb.EntryStorage
	// Whenever WriteEpochInfo is called, the EpochInfo object being written
	// in the storage is pushed into all epochInfo channels.
	epochInfo []chan *corepb.EpochInfo
}

// Create creates a storage object from an existing db connection.
func New(ctx context.Context) *MemStorage {
	s := &MemStorage{
		entries: make(map[uint64]*corepb.EntryStorage),
		epochs:  make(map[uint64]*corepb.EpochInfo),
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

// ReadEpochInfo reads an EpochInfo from the storage
func (s *MemStorage) ReadEpochInfo(ctx context.Context, epoch uint64) (*corepb.EpochInfo, error) {
	val, ok := s.epochs[epoch]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "%v Not Found", epoch)
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

	// Push entry in the channel in order to be added to the merkle tree.
	for _, ch := range s.updates {
		ch <- entry
	}
	return nil
}

// WriteEpochInfo writes the epoch information in the storage.
func (s *MemStorage) WriteEpochInfo(ctx context.Context, epoch uint64, info *corepb.EpochInfo) error {
	s.epochs[epoch] = info
	for _, ch := range s.epochInfo {
		ch <- info
	}
	return nil
}

// SubscribeUpdates subscribes an update channel. All EntryStorage will be
// transmitted on all subscribed channels.
func (s *MemStorage) SubscribeUpdates(ch chan *corepb.EntryStorage) {
	s.updates = append(s.updates, ch)
}

// SubscribeEpochInfo subscribes an epoch info channel. All EpochInfo will be
// transmitted on all subscribed channels.
func (s *MemStorage) SubscribeEpochInfo(ch chan *corepb.EpochInfo) {
	s.epochInfo = append(s.epochInfo, ch)
}
