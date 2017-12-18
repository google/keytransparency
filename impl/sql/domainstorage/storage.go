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

// Package domainstorage implements the domain.Storage interface.
package domainstorage

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/keytransparency/core/domain"
	"github.com/google/trillian/crypto/keyspb"
)

const (
	createSQL = `
CREATE TABLE IF NOT EXISTS Domains(
  DomainId              VARCHAR(40) NOT NULL,
  MapId                 BIGINT NOT NULL,
  LogId                 BIGINT NOT NULL,
  VRFPublicKey          MEDIUMBLOB NOT NULL,
  VRFPrivateKey         MEDIUMBLOB NOT NULL,
  MinInterval           BIGINT NOT NULL,
  MaxInterval           BIGINT NOT NULL,
  Deleted               INTEGER,
  DeleteTimeMillis      BIGINT,
  PRIMARY KEY(DomainId)
);`
	writeSQL = `INSERT INTO Domains 
(DomainId, MapId, LogId, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted) 
VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
	readSQL = `
SELECT DomainId, MapId, LogId, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Domains WHERE DomainId = ? AND Deleted = 0;`
	readDeletedSQL = `
SELECT DomainId, MapId, LogId, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Domains WHERE DomainId = ?;`
	listSQL = `
SELECT DomainId, MapId, LogId, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Domains WHERE Deleted = 0;`
	listDeletedSQL = `
SELECT DomainId, MapId, LogId, VRFPublicKey, VRFPrivateKey, MinInterval, MaxInterval, Deleted
FROM Domains;`
	setDeletedSQL = `UPDATE Domains SET Deleted = ?, DeleteTimeMillis = ? WHERE DomainId = ?`
)

type storage struct {
	db *sql.DB
}

// New returns a admin.Storage client backed by and SQL table.
func New(db *sql.DB) (domain.Storage, error) {
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
		return fmt.Errorf("Failed to create commitments tables: %v", err)
	}
	return nil
}

func (s *storage) List(ctx context.Context, showDeleted bool) ([]*domain.Domain, error) {
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

	ret := []*domain.Domain{}
	for rows.Next() {
		var pubkey, anyData []byte
		d := &domain.Domain{}
		if err := rows.Scan(
			&d.Domain,
			&d.MapID, &d.LogID,
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
		ret = append(ret, d)
	}
	return ret, nil
}

func (s *storage) Write(ctx context.Context, d *domain.Domain) error {
	// Prepare data.
	anyPB, err := ptypes.MarshalAny(d.VRFPriv)
	if err != nil {
		return err
	}
	anyData, err := proto.Marshal(anyPB)
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
		d.Domain,
		d.MapID, d.LogID,
		d.VRF.Der, anyData,
		d.MinInterval.Nanoseconds(), d.MaxInterval.Nanoseconds(),
		false)
	return err
}

func (s *storage) Read(ctx context.Context, domainID string, showDeleted bool) (*domain.Domain, error) {
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
	d := &domain.Domain{}
	var pubkey, anyData []byte
	if err := readStmt.QueryRowContext(ctx, domainID).Scan(
		&d.Domain,
		&d.MapID, &d.LogID,
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

func (s *storage) SetDelete(ctx context.Context, domainID string, isDeleted bool) error {
	_, err := s.db.ExecContext(ctx, setDeletedSQL, isDeleted, time.Now().Unix(), domainID)
	return err
}
