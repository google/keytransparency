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
	"encoding/binary"

	"github.com/golang/protobuf/proto"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	context "golang.org/x/net/context"
)

// LevelDBStorage holds state required to store data in a leveldb database.
// Create creates a new LevelDBStorage object.
type LevelDBStorage struct {
	// db is the leveldb database object.
	db *leveldb.DB
}

// OpebDB creates a LevelDBStorage with a leveldb.DB object pointing to the
// given path. If a file in the given path exists, it will open, otherwise it
// will be created.
func OpenDB(path string) (*LevelDBStorage, error) {
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while creating leveldb database: %v", err)
	}

	return &LevelDBStorage{db}, nil
}

// CloseDB closes the leveldb.DB database object.
func (s *LevelDBStorage) Close() {
	s.db.Close()
}

// Read reads a EntryStroage from the leveldb database.
func (s *LevelDBStorage) Read(ctx context.Context, primaryKey uint64) (*corepb.EntryStorage, error) {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, primaryKey)

	val, err := s.db.Get(key, nil)
	if err != nil {
		if err == errors.ErrNotFound {
			return nil, grpc.Errorf(codes.NotFound, "%v Not Found", primaryKey)
		}
		return nil, grpc.Errorf(codes.Internal, "Error while reading from leveldb database: %v", err)
	}

	entry := new(corepb.EntryStorage)
	if err := proto.Unmarshal(val, entry); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while unmarshaling storage entry: %v", err)
	}

	return entry, nil
}

// Write inserts a new EntryStorage in the leveldb database. This function works
// whether the entry exists or not. If the entry does not exist, it will be
// inserted, otherwise updated.
func (s *LevelDBStorage) Write(ctx context.Context, entry *corepb.EntryStorage) error {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, entry.CommitmentTimestamp)

	entryData, err := proto.Marshal(entry)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Error while marshaling entry storage: %v", err)
	}
	_ = entryData

	if err := s.db.Put(key, entryData, nil); err != nil {
		return grpc.Errorf(codes.Internal, "Error while writing to leveldb database: %v", err)
	}
	return nil
}
