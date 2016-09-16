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

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

const (
	mapRowExpr = `
	REPLACE INTO Maps (MapId) VALUES (?);`
	insertExpr = `
	INSERT INTO Commitments (MapId, Commitment, Value)
	VALUES (?, ?, ?);`
	readExpr = `
	SELECT Value FROM Commitments
	WHERE MapId = ? AND Commitment = ?;`
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
	createStmt := []string{
		`
	CREATE TABLE IF NOT EXISTS Maps (
		MapId   VARCHAR(32) NOT NULL,
		PRIMARY KEY(MapID)
	);`,
		`
	CREATE TABLE IF NOT EXISTS Commitments (
		MapId      VARCHAR(32) NOT NULL,
		Commitment VARCHAR(32) NOT NULL,
		Value      BLOB(1024)  NOT NULL,
		PRIMARY KEY(MapID, Commitment),
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	);`,
	}
	for _, stmt := range createStmt {
		_, err := c.db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("Failed to create commitments tables: %v", err)
		}
	}
	return nil
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
