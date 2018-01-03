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

	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

const (
	insertExpr = `
	INSERT INTO Mutations (MapID, MIndex, Mutation)
	VALUES (?, ?, ?);`
	readRangeExpr = `
  	SELECT Sequence, Mutation FROM Mutations
  	WHERE MapID = ? AND Sequence > ? AND Sequence <= ?
  	ORDER BY Sequence ASC LIMIT ?;`
	readAllExpr = `
 	SELECT Sequence, Mutation FROM Mutations
 	WHERE MapID = ? AND Sequence > ?
	ORDER BY Sequence ASC;`
)

type mutations struct {
	db *sql.DB
}

// New creates a new mutations instance.
func New(db *sql.DB) (mutator.MutationStorage, error) {
	m := &mutations{
		db: db,
	}

	// Create tables and map entry.
	if err := m.create(); err != nil {
		return nil, err
	}
	return m, nil
}

// ReadRange reads all mutations for a specific given mapID and sequence range.
// The range is identified by a starting sequence number and a count. Note that
// startSequence is not included in the result. ReadRange stops when endSequence
// or count is reached, whichever comes first. ReadRange also returns the maximum
// sequence number read.
func (m *mutations) ReadRange(ctx context.Context, mapID int64, startSequence, endSequence uint64, count int32) (uint64, []*pb.EntryUpdate, error) {
	readStmt, err := m.db.Prepare(readRangeExpr)
	if err != nil {
		return 0, nil, err
	}
	defer readStmt.Close()
	rows, err := readStmt.QueryContext(ctx, mapID, startSequence, endSequence, count)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	return readRows(rows)
}

// ReadAll reads all mutations starting from the given sequence number. Note that
// startSequence is not included in the result. ReadAll also returns the maximum
// sequence number read.
func (m *mutations) ReadAll(ctx context.Context, mapID int64, startSequence uint64) (uint64, []*pb.EntryUpdate, error) {
	readStmt, err := m.db.Prepare(readAllExpr)
	if err != nil {
		return 0, nil, err
	}
	defer readStmt.Close()
	rows, err := readStmt.QueryContext(ctx, mapID, startSequence)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	return readRows(rows)
}

func readRows(rows *sql.Rows) (uint64, []*pb.EntryUpdate, error) {
	results := make([]*pb.EntryUpdate, 0)
	maxSequence := uint64(0)
	for rows.Next() {
		var sequence uint64
		var mData []byte
		if err := rows.Scan(&sequence, &mData); err != nil {
			return 0, nil, err
		}
		if sequence > maxSequence {
			maxSequence = sequence
		}
		mutation := new(pb.EntryUpdate)
		if err := proto.Unmarshal(mData, mutation); err != nil {
			return 0, nil, err
		}
		results = append(results, mutation)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	return maxSequence, results, nil
}

// Write saves the mutation in the database. Write returns the auto-inserted
// sequence number.
func (m *mutations) Write(ctx context.Context, mapID int64, update *pb.EntryUpdate) (uint64, error) {
	index := update.GetMutation().GetIndex()
	mData, err := proto.Marshal(update)
	if err != nil {
		return 0, err
	}

	writeStmt, err := m.db.Prepare(insertExpr)
	if err != nil {
		return 0, err
	}
	defer writeStmt.Close()
	result, err := writeStmt.ExecContext(ctx, mapID, index, mData)
	if err != nil {
		return 0, err
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	return uint64(sequence), nil
}

// Create creates new database tables.
func (m *mutations) create() error {
	for _, stmt := range createStmt {
		_, err := m.db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("Failed to create mutation tables: %v", err)
		}
	}
	return nil
}
