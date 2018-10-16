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

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

const (
	insertMutationsExpr = `
	INSERT INTO Mutations (DomainID, Revision, Sequence, Mutation)
	VALUES (?, ?, ?, ?);`
	readMutationsExpr = `
  	SELECT Sequence, Mutation FROM Mutations
  	WHERE DomainID = ? AND Revision = ? AND Sequence >= ?
  	ORDER BY Sequence ASC LIMIT ?;`
)

var (
	createStmt = []string{
		`CREATE TABLE IF NOT EXISTS Mutations (
		DomainID VARCHAR(30)   NOT NULL,
		Revision BIGINT        NOT NULL,
		Sequence INTEGER       NOT NULL,
		Mutation BLOB          NOT NULL,
		PRIMARY KEY(DomainID, Revision, Sequence)
	);`,
		`CREATE TABLE IF NOT EXISTS Batches (
		DomainID VARCHAR(30)   NOT NULL,
		Revision BIGINT        NOT NULL,
		LogID    BIGINT        NOT NULL,
		Low      BIGINT        NOT NULL, 
		High     BIGINT        NOT NULL,
		PRIMARY KEY(DomainID, Revision, LogID)
	);`,
		`CREATE TABLE IF NOT EXISTS Queue (
		DomainID VARCHAR(30)   NOT NULL,
		LogID    BIGINT        NOT NULL,
		Time     BIGINT        NOT NULL,
		Mutation BLOB          NOT NULL,
		PRIMARY KEY(DomainID, LogID, Time)
	);`,
		`CREATE TABLE IF NOT EXISTS Logs (
		DomainID VARCHAR(30)   NOT NULL,
		LogID    BIGINT        NOT NULL,
		Enabled  INTEGER       NOT NULL,
		PRIMARY KEY(DomainID, LogID)
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
			return fmt.Errorf("Failed to create mutation tables: %v", err)
		}
	}
	return nil
}

// ReadPage reads all mutations for a specific given domainID and sequence range.
// The range is identified by a starting sequence number and a count. Note that
// startSequence is not included in the result. ReadRange stops when endSequence
// or count is reached, whichever comes first. ReadRange also returns the maximum
// sequence number read.
func (m *Mutations) ReadPage(ctx context.Context, domainID string, revision, start int64, pageSize int32) (int64, []*pb.Entry, error) {
	readStmt, err := m.db.Prepare(readMutationsExpr)
	if err != nil {
		return 0, nil, err
	}
	defer readStmt.Close()
	rows, err := readStmt.QueryContext(ctx, domainID, revision, start, pageSize)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	return readMutations(rows)
}

// WriteBatch saves the mutations in the database.
func (m *Mutations) WriteBatch(ctx context.Context, domainID string, revision int64, mutations []*pb.Entry) error {
	writeStmt, err := m.db.Prepare(insertMutationsExpr)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	for i, m := range mutations {
		mData, err := proto.Marshal(m)
		if err != nil {
			return err
		}
		if _, err := writeStmt.ExecContext(ctx, domainID, revision, i, mData); err != nil {
			return err
		}
	}
	return nil
}

func readMutations(rows *sql.Rows) (int64, []*pb.Entry, error) {
	results := make([]*pb.Entry, 0)
	maxSequence := int64(0)
	for rows.Next() {
		var sequence int64
		var mData []byte
		if err := rows.Scan(&sequence, &mData); err != nil {
			return 0, nil, err
		}
		if sequence > maxSequence {
			maxSequence = sequence
		}
		entry := new(pb.Entry)
		if err := proto.Unmarshal(mData, entry); err != nil {
			return 0, nil, err
		}
		results = append(results, entry)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return maxSequence, results, nil
}

// WriteBatchSources saves the mutations in the database.
// If revision has alredy been defined, this will fail.
func (m *Mutations) WriteBatchSources(ctx context.Context, domainID string, revision int64,
	sources map[int64]*spb.MapMetadata_SourceSlice) error {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	// Search for existing domainID/revision.
	var count int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM Batches WHERE DomainID = ? AND Revision = ?;`,
		domainID, revision).Scan(&count); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("could not roll back: %v", rollbackErr)
		}
		return fmt.Errorf("error querying batch definition: %v", err)
	}
	if count > 0 {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("could not roll back: %v", rollbackErr)
		}
		return status.Errorf(codes.AlreadyExists,
			"a batch definition for %v rev %v already exists with %v logs",
			domainID, revision, count)
	}

	for logID, source := range sources {
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO Batches (DomainID, Revision, LogID, Low, High) VALUES (?, ?, ?, ?, ?);`,
			domainID, revision, logID, source.LowestWatermark, source.HighestWatermark); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return fmt.Errorf("could not roll back: %v", rollbackErr)
			}
			return fmt.Errorf("insert batch boundary (%v, %v, %v, %v) failed: %v",
				domainID, revision, logID, source, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit failed: %v", err)
	}
	return nil
}

// ReadBatch returns the batch definitions for a given revision.
func (m *Mutations) ReadBatch(ctx context.Context, domainID string,
	revision int64) (map[int64]*spb.MapMetadata_SourceSlice, error) {
	watermarks := make(map[int64]*spb.MapMetadata_SourceSlice)
	rows, err := m.db.QueryContext(ctx,
		`SELECT LogID, Low, High FROM Batches WHERE DomainID = ? AND Revision = ?;`,
		domainID, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var logID, low, high int64
		if err := rows.Scan(&logID, &low, &high); err != nil {
			return nil, err
		}
		watermarks[logID] = &spb.MapMetadata_SourceSlice{
			LowestWatermark:  low,
			HighestWatermark: high,
		}

	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return watermarks, nil
}
