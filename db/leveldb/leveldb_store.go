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

package leveldb

import (
	"bytes"
	"encoding/binary"

	"github.com/golang/leveldb"
	"github.com/golang/leveldb/db"
	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/security_e2ekeys_core"
)

// LevelDBStorage holds state required to store data in a leveldb database.
// Create creates a new LevelDBStorage object.
type LevelDBStorage struct {
	updates *leveldb.DB
	epochs  *leveldb.DB
}

// OpebDB creates a LevelDBStorage with a leveldb.DB object pointing to the
// given path. If a file in the given path exists, it will open, otherwise it
// will be created.
func Open(path string) (*LevelDBStorage, error) {
	// Create updates leveldb database.
	updates, err := leveldb.Open(path+"/updates", nil)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while creating updates database: %v", err)
	}
	// Create epochs leveldb database.
	epochs, err := leveldb.Open(path+"/epochs", nil)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while creating epochs info database: %v", err)
	}

	return &LevelDBStorage{updates, epochs}, nil
}

// CloseDB closes the leveldb.DB database object.
func (s *LevelDBStorage) Close() {
	s.updates.Close()
	s.epochs.Close()
}

// ReadUpdate reads a EntryStroage from the leveldb database.
func (s *LevelDBStorage) ReadUpdate(ctx context.Context, primaryKey int64) (*corepb.EntryStorage, error) {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, primaryKey)

	val, err := s.updates.Get(buff.Bytes(), nil)
	if err != nil {
		if err == db.ErrNotFound {
			return nil, grpc.Errorf(codes.NotFound, "%v Not Found", primaryKey)
		}
		return nil, grpc.Errorf(codes.Internal, "Error while reading from updates database: %v", err)
	}

	entry := new(corepb.EntryStorage)
	if err := proto.Unmarshal(val, entry); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while unmarshaling storage entry: %v", err)
	}

	return entry, nil
}

// ReadEpochInfo reads an EpochInfo from the storage
func (s *LevelDBStorage) ReadEpochInfo(ctx context.Context, primaryKey int64) (*corepb.EpochInfo, error) {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, primaryKey)

	val, err := s.epochs.Get(buff.Bytes(), nil)
	if err != nil {
		if err == db.ErrNotFound {
			return nil, grpc.Errorf(codes.NotFound, "%v Not Found", primaryKey)
		}
		return nil, grpc.Errorf(codes.Internal, "Error while reading from epochs database: %v", err)
	}

	epochInfo := new(corepb.EpochInfo)
	if err := proto.Unmarshal(val, epochInfo); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while unmarshaling epoch info: %v", err)
	}

	return epochInfo, nil
}

// WriteUpdate inserts a new EntryStorage in the leveldb database. This function
// works whether the entry exists or not. If the entry does not exist, it will
// be inserted, otherwise updated.
func (s *LevelDBStorage) WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, entry.CommitmentTimestamp)

	entryData, err := proto.Marshal(entry)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Error while marshaling entry storage: %v", err)
	}

	if err := s.updates.Set(buff.Bytes(), entryData, nil); err != nil {
		return grpc.Errorf(codes.Internal, "Error while writing to updates database: %v", err)
	}
	return nil
}

// WriteEpochInfo writes the epoch information in the storage.
func (s *LevelDBStorage) WriteEpochInfo(ctx context.Context, primaryKey int64, epochInfo *corepb.EpochInfo) error {
	buff := new(bytes.Buffer)
	binary.Write(buff, binary.BigEndian, primaryKey)

	epochInfoData, err := proto.Marshal(epochInfo)
	if err != nil {
		return grpc.Errorf(codes.Internal, "Error while marshaling epoch info: %v", err)
	}

	if err := s.epochs.Set(buff.Bytes(), epochInfoData, nil); err != nil {
		return grpc.Errorf(codes.Internal, "Error while writing to epochs database: %v", err)
	}
	return nil
}
