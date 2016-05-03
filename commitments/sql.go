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
	"database/sql"
	"log"

	"golang.org/x/net/context"
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

type Commitments struct {
	mapID []byte
	db    *sql.DB
	epoch int64 // The currently valid epoch. Insert at epoch+1.
}

// NewSQL returns a new SQL backed commitment db.
func New(db *sql.DB, mapID string) *Commitments {
	c := &Commitments{
		mapID: []byte(mapID),
		db:    db,
	}

	// Create tables.
	_, err := db.Exec(createExpr)
	if err != nil {
		log.Fatalf("Failed to create commitment tables: %v", err)
	}
	c.insertMapRow()
	return c
}

// WriteCommitment saves a commitment to the database.
func (c *Commitments) WriteCommitment(ctx context.Context, commitment, key, value []byte) error {
	stmt, err := c.db.Prepare(insertExpr)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(c.mapID, commitment, key, value)
	return err
}

// ReadCommitment retrieves a commitment from the database.
func (c *Commitments) ReadCommitment(ctx context.Context, commitment []byte) (*Commitment, error) {
	stmt, err := c.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	value := &Commitment{}
	if err := stmt.QueryRow(c.mapID, commitment).Scan(&value.Key, &value.Data); err == sql.ErrNoRows {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return value, nil

}

func (c *Commitments) insertMapRow() {
	stmt, err := c.db.Prepare(mapRowExpr)
	if err != nil {
		log.Fatalf("Failed preparing mapID insert statement: %v", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(c.mapID)
	if err != nil {
		log.Fatalf("Failed executing mapID insert: %v", err)
	}
}
