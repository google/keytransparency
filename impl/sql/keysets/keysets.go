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
	"context"
	"database/sql"
	"fmt"

	"github.com/google/keytransparency/core/storage"

	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/api/type/type_go_proto"
)

const (
	schema = `
CREATE TABLE IF NOT EXISTS KeySets(
InstanceID            BIGINT NOT NULL,
DomainID              VARCHAR(40) NOT NULL,
AppID                 VARCHAR(40) NOT NULL,
KeySet                MEDIUMBLOB NOT NULL,
PRIMARY KEY(InstanceID,DomainID,AppID)
);`

	getSQL = `SELECT * FROM KeySets WHERE InstanceID = ? AND DomainID = ? AND AppID = ?`
	setSQL = `INSERT INTO KeySets (InstanceID, DomainID, AppID, KeySet) VALUES (?, ?, ?, ?);`
)

// Storage stores keysets, backed by an SQL database.
type Storage struct {
	db *sql.DB
}

type keyset struct {
	InstanceID int64
	DomainID   string
	AppID      string
	KeySet     []byte
}

// newKeyset converts a tpb.KeySet to keyset.
func newKeyset(instance int64, domainID, appID string, k *tpb.KeySet) (*keyset, error) {
	data, err := proto.Marshal(k)
	if err != nil {
		return nil, err
	}
	return &keyset{
		InstanceID: instance,
		DomainID:   domainID,
		AppID:      appID,
		KeySet:     data,
	}, nil
}

// Proto converts a keyset to a tpb.KeySet proto.
func (k *keyset) Proto() (*tpb.KeySet, error) {
	ks := tpb.KeySet{}
	if err := proto.Unmarshal(k.KeySet, &ks); err != nil {
		return nil, err
	}
	return &ks, nil
}

// New returns a storage.KeySets client backed by an SQL table.
func New(db *sql.DB) (storage.KeySets, error) {
	s := &Storage{db: db}
	// Create schema.
	if _, err := s.db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create keyset table: %v", err)
	}
	return s, db.Ping()
}

// Get returns a stored keyset.
func (s *Storage) Get(ctx context.Context, instance int64, domainID, appID string) (*tpb.KeySet, error) {
	readStmt, err := s.db.PrepareContext(ctx, getSQL)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()
	r := keyset{}
	if err := readStmt.QueryRowContext(ctx, instance, domainID, appID).Scan(
		&r.InstanceID,
		&r.DomainID,
		&r.AppID,
		&r.KeySet); err != nil {
		return nil, err
	}
	return r.Proto()
}

// Set saves a keyset.
func (s *Storage) Set(ctx context.Context, instance int64, domainID, appID string, k *tpb.KeySet) error {
	r, err := newKeyset(instance, domainID, appID, k)
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
		r.DomainID,
		r.AppID,
		r.KeySet)
	return err
}
