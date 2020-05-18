// Copyright 2017 Google Inc. All Rights Reserved.
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

// Package directory implements the directory.Storage interface.
package directory

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/keytransparency/core/directory"
	tpb "github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	createSQL = `
CREATE TABLE IF NOT EXISTS Directories(
  DirectoryId           VARCHAR(40) NOT NULL,
  Map                   BLOB NOT NULL,
  Log                   BLOB NOT NULL,
  VRFPublicKey          MEDIUMBLOB NOT NULL,
  VRFPrivateKey         MEDIUMBLOB NOT NULL,
  MinInterval           BIGINT NOT NULL,
  MaxInterval           BIGINT NOT NULL,
  Deleted               INTEGER,
  DeleteTimeSeconds      BIGINT,
  PRIMARY KEY(DirectoryId)
);`
	writeSQL = `INSERT INTO Directories
(DirectoryId, Map, Log, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted, DeleteTimeSeconds)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);`
	readSQL = `
SELECT DirectoryId, Map, Log, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted, DeleteTimeSeconds
FROM Directories WHERE DirectoryId = ? AND Deleted = 0;`
	readDeletedSQL = `
SELECT DirectoryId, Map, Log, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted, DeleteTimeSeconds
FROM Directories WHERE DirectoryId = ?;`
	listSQL = `
SELECT DirectoryId, Map, Log, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Directories WHERE Deleted = 0;`
	listDeletedSQL = `
SELECT DirectoryId, Map, Log, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Directories;`
	setDeletedSQL = `UPDATE Directories SET Deleted = ?, DeleteTimeSeconds = ? WHERE DirectoryId = ?`
	deleteSQL     = `DELETE FROM Directories WHERE DirectoryId = ?`
)

type storage struct {
	db *sql.DB
}

// NewStorage returns a directory.Storage client backed by an SQL table.
func NewStorage(db *sql.DB) (directory.Storage, error) {
	s := &storage{
		db: db,
	}
	// Create tables.
	if err := s.create(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *storage) create() error {
	_, err := s.db.Exec(createSQL)
	if err != nil {
		return fmt.Errorf("failed to create commitments tables: %v", err)
	}
	return nil
}

func (s *storage) List(ctx context.Context, showDeleted bool) ([]*directory.Directory, error) {
	var query string
	if showDeleted {
		query = listDeletedSQL
	} else {
		query = listSQL
	}
	readStmt, err := s.db.PrepareContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()

	rows, err := readStmt.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ret := []*directory.Directory{}
	for rows.Next() {
		var pubkey, anyData, mapByte, logByte []byte
		var logTree tpb.Tree
		var mapTree tpb.Tree
		d := &directory.Directory{}
		if err := rows.Scan(
			&d.DirectoryID,
			&mapByte, &logByte,
			&pubkey, &anyData,
			&d.MinInterval, &d.MaxInterval,
			&d.Deleted); err != nil {
			return nil, err
		}
		// Unwrap protos.
		d.VRF = &keyspb.PublicKey{Der: pubkey}
		d.VRFPriv, err = unwrapAnyProto(anyData)
		if err != nil {
			return nil, err
		}
		err = proto.Unmarshal(logByte, &logTree)
		if err != nil {
			return nil, err
		}
		err = proto.Unmarshal(mapByte, &mapTree)
		if err != nil {
			return nil, err
		}
		d.Map = &mapTree
		d.Log = &logTree
		ret = append(ret, d)
	}
	return ret, nil
}

func (s *storage) Write(ctx context.Context, d *directory.Directory) error {
	// Prepare data.
	anyPB, err := ptypes.MarshalAny(d.VRFPriv)
	if err != nil {
		return err
	}
	anyData, err := proto.Marshal(anyPB)
	if err != nil {
		return err
	}
	mapTree, err := proto.Marshal(d.Map)
	if err != nil {
		return err
	}
	logTree, err := proto.Marshal(d.Log)
	if err != nil {
		return err
	}
	// Prepare SQL.
	writeStmt, err := s.db.PrepareContext(ctx, writeSQL)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.ExecContext(ctx,
		d.DirectoryID,
		mapTree, logTree,
		d.VRF.Der, anyData,
		d.MinInterval.Nanoseconds(), d.MaxInterval.Nanoseconds(),
		false,
		// Store January 1, year 1, 00:00:00 UTC, the time.Time zero value.
		// Store this as unix seconds till Jan 1 1970, a large negative number.
		time.Time{}.Unix())
	return err
}

func (s *storage) Read(ctx context.Context, directoryID string, showDeleted bool) (*directory.Directory, error) {
	var SQL string
	if showDeleted {
		SQL = readDeletedSQL
	} else {
		SQL = readSQL
	}
	readStmt, err := s.db.PrepareContext(ctx, SQL)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()
	d := &directory.Directory{}
	var pubkey, anyData []byte
	var deletedUnix int64
	var mapByte []byte
	var logByte []byte
	var logTree tpb.Tree
	var mapTree tpb.Tree

	if err := readStmt.QueryRowContext(ctx, directoryID).Scan(
		&d.DirectoryID,
		&mapByte, &logByte,
		&pubkey, &anyData,
		&d.MinInterval, &d.MaxInterval,
		&d.Deleted,
		&deletedUnix,
	); err == sql.ErrNoRows {
		return nil, status.Errorf(codes.NotFound, "%v", err)
	} else if err != nil {
		return nil, err
	}
	// Unwrap protos.
	d.VRF = &keyspb.PublicKey{Der: pubkey}
	d.VRFPriv, err = unwrapAnyProto(anyData)
	d.DeletedTimestamp = time.Unix(deletedUnix, 0)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(logByte, &logTree)
	if err != nil {
		return nil, err
	}
	err = proto.Unmarshal(mapByte, &mapTree)
	if err != nil {
		return nil, err
	}
	d.Map = &mapTree
	d.Log = &logTree

	return d, nil
}

// unwrapAnyProto returns the proto object seralized inside a serialized any.Any
func unwrapAnyProto(anyData []byte) (proto.Message, error) {
	var anyPB any.Any
	if err := proto.Unmarshal(anyData, &anyPB); err != nil {
		return nil, err
	}
	var privKey ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(&anyPB, &privKey); err != nil {
		return nil, err
	}
	return privKey.Message, nil
}

func (s *storage) SetDelete(ctx context.Context, directoryID string, isDeleted bool) error {
	_, err := s.db.ExecContext(ctx, setDeletedSQL, isDeleted, time.Now().Unix(), directoryID)
	return err
}

// Delete permanently deletes a directory.
func (s *storage) Delete(ctx context.Context, directoryID string) error {
	_, err := s.db.ExecContext(ctx, deleteSQL, directoryID)
	return err
}
