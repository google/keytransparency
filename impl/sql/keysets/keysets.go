// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package keysets implements the storage.KeySets interface.
package keysets

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"

	"github.com/golang/protobuf/proto"

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
)

const (
	schema = `
CREATE TABLE IF NOT EXISTS KeySets(
InstanceID            BIGINT NOT NULL,
DirectoryID           VARCHAR(40) NOT NULL,
KeySet                MEDIUMBLOB NOT NULL,
PRIMARY KEY(InstanceID,DirectoryID)
);`

	getSQL = `SELECT * FROM KeySets WHERE InstanceID = ? AND DirectoryID = ?`
	setSQL = `INSERT INTO KeySets (InstanceID, DirectoryID, KeySet) VALUES (?, ?, ?);`
)

// Storage stores keysets, backed by an SQL database.
type Storage struct {
	db *sql.DB
}

type keysetRow struct {
	InstanceID  int64
	DirectoryID string
	KeySet      []byte
}

// newKeyset converts a tpb.KeySet to keyset.
func newKeyset(instance int64, directoryID string, k *keyset.Handle) (*keysetRow, error) {
	serializedKeyset, err := proto.Marshal(k.Keyset())
	if err != nil {
		return nil, err
	}
	return &keysetRow{
		InstanceID:  instance,
		DirectoryID: directoryID,
		KeySet:      serializedKeyset,
	}, nil
}

// Proto converts a keyset to a tpb.KeySet proto.
func (k *keysetRow) Proto() (*keyset.Handle, error) {
	return insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewBuffer(k.KeySet)))
}

// New returns a storage.KeySets client backed by an SQL table.
func New(db *sql.DB) (*Storage, error) {
	s := &Storage{db: db}
	// Create schema.
	if _, err := s.db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create keyset table: %v", err)
	}
	return s, db.Ping()
}

// Get returns a stored keysetRow.
func (s *Storage) Get(ctx context.Context, instance int64, directoryID string) (*keyset.Handle, error) {
	readStmt, err := s.db.PrepareContext(ctx, getSQL)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()
	r := keysetRow{}
	if err := readStmt.QueryRowContext(ctx, instance, directoryID).Scan(
		&r.InstanceID,
		&r.DirectoryID,
		&r.KeySet); err != nil {
		return nil, err
	}

	return r.Proto()
}

// Set saves a keyset.
func (s *Storage) Set(ctx context.Context, instance int64, directoryID string, k *keyset.Handle) error {
	r, err := newKeyset(instance, directoryID, k)
	if err != nil {
		return err
	}

	// Prepare SQL.
	writeStmt, err := s.db.PrepareContext(ctx, setSQL)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.ExecContext(ctx,
		r.InstanceID,
		r.DirectoryID,
		r.KeySet)
	return err
}
