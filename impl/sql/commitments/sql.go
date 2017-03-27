// Copyright 2016 Google Inc. All Rights Reserved.
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
	"database/sql"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

const (
	insertMapRowExpr = `INSERT INTO Maps (MapID) VALUES (?);`
	countMapRowExpr  = `SELECT COUNT(*) AS count FROM Maps WHERE MapID = ?;`
	insertExpr       = `
	INSERT INTO Commitments (MapID, Commitment, Value)
	VALUES (?, ?, ?);`
	readExpr = `
	SELECT Value FROM Commitments
	WHERE MapID = ? AND Commitment = ?;`
)

var (
	createStmt = []string{
		`
	CREATE TABLE IF NOT EXISTS Maps (
		MapID   BIGINT NOT NULL,
		PRIMARY KEY(MapID)
	);`,
		`
	CREATE TABLE IF NOT EXISTS Commitments (
		MapID      BIGINT        NOT NULL,
		Commitment VARBINARY(32) NOT NULL,
		Value      BLOB(1024)    NOT NULL,
		PRIMARY KEY(MapID, Commitment),
		FOREIGN KEY(MapID) REFERENCES Maps(MapID) ON DELETE CASCADE
	);`,
	}
	errDoubleCommitment = errors.New("Commitment to different key-value")
)

// Commitments stores cryptographic commitments.
type Commitments struct {
	mapID int64
	db    *sql.DB
}

// New returns a new SQL backed commitment db.
func New(db *sql.DB, mapID int64) (*Commitments, error) {
	c := &Commitments{
		mapID: mapID,
		db:    db,
	}

	// Create tables.
	if err := c.create(); err != nil {
		return nil, err
	}
	if err := c.insertMapRow(); err != nil {
		return nil, err
	}
	return c, nil
}

// WriteCommitment saves a commitment to the database.
// Writes if the same commitment value succeeds.
func (c *Commitments) Write(ctx context.Context, commitment []byte, committed *tpb.Committed) (returnErr error) {
	tx, err := c.db.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if returnErr != nil {
			if rbErr := tx.Rollback(); rbErr != nil {
				returnErr = fmt.Errorf("neighborsAt failed: %v, and Rollback failed: %v", err, rbErr)
			}
			return
		}
		returnErr = tx.Commit()
	}()

	readStmt, err := tx.Prepare(readExpr)
	if err != nil {
		return err
	}
	defer readStmt.Close()

	// Read existing commitment.
	var value []byte
	switchErr := readStmt.QueryRow(c.mapID, commitment).Scan(&value)
	switch {
	case switchErr == sql.ErrNoRows:
		writeStmt, err := tx.Prepare(insertExpr)
		if err != nil {
			return err
		}
		defer writeStmt.Close()
		b, err := proto.Marshal(committed)
		if err != nil {
			return err
		}
		if _, err := writeStmt.Exec(c.mapID, commitment, b); err != nil {
			return err
		}
	case switchErr != nil:
		return switchErr
	default: // switchErr == nil
		var c tpb.Committed
		if err := proto.Unmarshal(value, &c); err != nil {
			return err
		}
		if !proto.Equal(committed, &c) {
			return errDoubleCommitment
		}
		// Write of existing value.
	}
	return nil
}

// Read retrieves a commitment from the database.
func (c *Commitments) Read(ctx context.Context, commitment []byte) (*tpb.Committed, error) {
	stmt, err := c.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var value []byte
	if err := stmt.QueryRow(c.mapID, commitment).Scan(&value); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}

	var committed tpb.Committed
	if err := proto.Unmarshal(value, &committed); err != nil {
		return nil, err
	}
	return &committed, nil
}

// Create creates a new database.
func (c *Commitments) create() error {
	for _, stmt := range createStmt {
		_, err := c.db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("Failed to create commitments tables: %v", err)
		}
	}
	return nil
}

func (c *Commitments) insertMapRow() error {
	// Check if a map row does not exist for the same MapID.
	countStmt, err := c.db.Prepare(countMapRowExpr)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	defer countStmt.Close()
	var count int
	if err := countStmt.QueryRow(c.mapID).Scan(&count); err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	if count >= 1 {
		return nil
	}

	// Insert a map row if it does not exist already.
	insertStmt, err := c.db.Prepare(insertMapRowExpr)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	defer insertStmt.Close()
	_, err = insertStmt.Exec(c.mapID)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	return nil
}
