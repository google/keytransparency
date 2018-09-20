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

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

const (
	insertMutationsExpr = `
	INSERT INTO Mutations (DomainID, Revision, Sequence, Mutation)
	VALUES (?, ?, ?, ?);`
	readMutationsExpr = `
  	SELECT Sequence, Mutation FROM Mutations
  	WHERE DomainID = ? AND Revision = ? AND Sequence >= ?
  	ORDER BY Sequence ASC LIMIT ?;`
	readQueueWatermarkExpr = `
	SELECT Time FROM Queue WHERE DomainID = ? ORDER BY TIME DESC LIMIT 1;`
	readQueueExpr = `
 	SELECT Time, Mutation FROM Queue
 	WHERE DomainID = ? AND
	TIME > ? AND TIME <= ?
	ORDER BY Time ASC;`
	deleteQueueExpr = `
	DELETE FROM Queue
	WHERE DomainID = ? AND Time = ?;`
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
		`CREATE TABLE IF NOT EXISTS Queue (
		DomainID VARCHAR(30)   NOT NULL,
		Time     BIGINT        NOT NULL,
		Mutation BLOB          NOT NULL,
		PRIMARY KEY(DomainID, Time)
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
