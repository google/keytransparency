// Copyright 2016 Google Inc. All Rights Reserved.
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

// Package mutationstorage defines operations to write and read mutations to
// and from the database.
package mutationstorage

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

var (
	createStmt = []string{
		`CREATE TABLE IF NOT EXISTS Batches (
		DomainID VARCHAR(30)   NOT NULL,
		Revision BIGINT        NOT NULL,
		Sources  BLOB          NOT NULL,
		PRIMARY KEY(DomainID, Revision)
	);`,
		`CREATE TABLE IF NOT EXISTS Queue (
		DirectoryID VARCHAR(30) NOT NULL,
		LogID       BIGINT      NOT NULL,
		TimeMicros  BIGINT      NOT NULL, -- In microseconds from Unix epoch.
		LocalID     BIGINT      NOT NULL,
		Mutation    BLOB        NOT NULL,
		PRIMARY KEY(DirectoryID, LogID, TimeMicros, LocalID)
	);`,
		`CREATE TABLE IF NOT EXISTS Logs (
		DirectoryID VARCHAR(30)   NOT NULL,
		LogID    BIGINT           NOT NULL,
		Enabled  INTEGER          NOT NULL,
		PRIMARY KEY(DirectoryID, LogID)
	);`,
	}
)

// Mutations implements mutator.MutationStorage and mutator.MutationQueue.
type Mutations struct {
	db *sql.DB
}

// New creates a new Mutations instance.
func New(db *sql.DB) (*Mutations, error) {
	m := &Mutations{
		db: db,
	}

	// Create tables.
	if err := m.createTables(); err != nil {
		return nil, err
	}
	return m, nil
}

// createTables creates new database tables.
func (m *Mutations) createTables() error {
	for _, stmt := range createStmt {
		_, err := m.db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("failed to create mutation tables: %v", err)
		}
	}
	return nil
}

// WriteBatchSources saves the mutations in the database.
// If revision has already been defined, this will fail.
func (m *Mutations) WriteBatchSources(ctx context.Context, dirID string, rev int64,
	sources *spb.MapMetadata) error {
	sourceData, err := proto.Marshal(sources)
	if err != nil {
		return fmt.Errorf("proto.Marshal(): %v", err)
	}
	if _, err := m.db.ExecContext(ctx,
		`INSERT INTO Batches (DomainID, Revision, Sources) VALUES (?, ?, ?);`,
		dirID, rev, sourceData); err != nil {
		return fmt.Errorf("insert batch boundary (%v, %v) failed: %v", dirID, rev, err)
	}
	return nil
}

// ReadBatch returns the batch definitions for a given revision.
func (m *Mutations) ReadBatch(ctx context.Context, domainID string, rev int64) (*spb.MapMetadata, error) {
	var sourceData []byte
	if err := m.db.QueryRowContext(ctx,
		`SELECT Sources FROM Batches WHERE DomainID = ? AND Revision = ?;`,
		domainID, rev).Scan(&sourceData); err == sql.ErrNoRows {
		return nil, status.Errorf(codes.NotFound, "revision %v not found", rev)
	} else if err != nil {
		return nil, err
	}

	var mapMetadata spb.MapMetadata
	if err := proto.Unmarshal(sourceData, &mapMetadata); err != nil {
		return nil, err
	}

	return &mapMetadata, nil
}

// HighestRev returns the highest defined revision number for directoryID.
func (m *Mutations) HighestRev(ctx context.Context, directoryID string) (int64, error) {
	var rev int64
	if err := m.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(Revision), 0) FROM Batches WHERE DomainID = ?`,
		directoryID).Scan(&rev); err != nil {
		return 0, err
	}
	return rev, nil
}
