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

package commitments

import (
	"bytes"
	"database/sql"
	"errors"
	"fmt"

	"golang.org/x/net/context"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

const (
	createExpr = `
	CREATE TABLE IF NOT EXISTS Maps (
		MapId	BLOB(32),
		PRIMARY KEY(MapID)
	);

	CREATE TABLE IF NOT EXISTS Commitments (
		MapId	BLOB(32) NOT NULL,
		Commitment BLOB(32) NOT NULL,
		Key	BLOB(16) NOT NULL,
		Value	BLOB(1024) NOT NULL,
		PRIMARY KEY(MapID, Commitment),
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	);`
	mapRowExpr = `
	INSERT OR IGNORE INTO Maps (MapId) VALUES ($1);`
	insertExpr = `
	INSERT INTO Commitments (MapId, Commitment, Key, Value)
	VALUES ($1, $2, $3, $4);`
	readExpr = `
	SELECT Key, Value FROM Commitments
	WHERE MapId = $1 AND Commitment = $2;`
)

var errDoubleCommitment = errors.New("Commitment to different key-value")

// Commitments stores cryptographic commitments.
type Commitments struct {
	mapID []byte
	db    *sql.DB
	epoch int64 // The currently valid epoch. Insert at epoch+1.
}

// New returns a new SQL backed commitment db.
func New(db *sql.DB, mapID string) (*Commitments, error) {
	c := &Commitments{
		mapID: []byte(mapID),
		db:    db,
	}

	// Create tables.
	_, err := db.Exec(createExpr)
	if err != nil {
		return nil, fmt.Errorf("Failed to create commitment tables: %v", err)
	}
	if err := c.insertMapRow(); err != nil {
		return nil, err
	}
	return c, nil
}

// WriteCommitment saves a commitment to the database.
// Writes if the same commitment value succeeds.
func (c *Commitments) Write(ctx context.Context, commitment []byte, committed *tpb.Committed) error {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	readStmt, err := tx.Prepare(readExpr)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer readStmt.Close()

	// Read existing commitment.
	read := &tpb.Committed{}

	err = readStmt.QueryRow(c.mapID, commitment).Scan(&read.Key, &read.Data)
	switch {
	case err == sql.ErrNoRows:
		writeStmt, err := tx.Prepare(insertExpr)
		if err != nil {
			tx.Rollback()
			return err
		}
		defer writeStmt.Close()
		if _, err := writeStmt.Exec(c.mapID, commitment, committed.Key, committed.Data); err != nil {
			tx.Rollback()
			return err
		}
		return tx.Commit()
	case err != nil:
		tx.Rollback()
		return err
	default: // err == nil
		if bytes.Equal(committed.Key, read.Key) && bytes.Equal(committed.Data, read.Data) {
			// Write of existing value.
			return tx.Commit()
		}
		tx.Rollback()
		return errDoubleCommitment
	}
}

// Read retrieves a commitment from the database.
func (c *Commitments) Read(ctx context.Context, commitment []byte) (*tpb.Committed, error) {
	stmt, err := c.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	value := &tpb.Committed{}
	if err := stmt.QueryRow(c.mapID, commitment).Scan(&value.Key, &value.Data); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return value, nil
}

func (c *Commitments) insertMapRow() error {
	stmt, err := c.db.Prepare(mapRowExpr)
	if err != nil {
		return fmt.Errorf("Failed preparing mapID insert statement: %v", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(c.mapID)
	if err != nil {
		return fmt.Errorf("Failed executing mapID insert: %v", err)
	}
	return nil
}
