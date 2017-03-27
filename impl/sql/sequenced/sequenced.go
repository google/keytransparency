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

// Package sequenced stores a list of objects that have been sequenced.
package sequenced

import (
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"fmt"

	"github.com/google/keytransparency/core/sequenced"
	"github.com/google/keytransparency/core/transaction"
)

const (
	insertMapRowExpr = `INSERT INTO Maps (MapID) VALUES (?);`
	countMapRowExpr  = `SELECT COUNT(*) AS count FROM Maps WHERE MapID = ?;`
	insertExpr       = `
	INSERT INTO Sequenced (MapID, Epoch, Data)
	VALUES (?, ?, ?);`
	readExpr = `
	SELECT Data FROM Sequenced
	WHERE MapID = ? AND Epoch = ?;`
	latestExpr = `
	SELECT Epoch, Data FROM Sequenced
	WHERE MapID = ? 
	ORDER BY Epoch DESC LIMIT 1;`
)

var (
	createStmt = []string{
		`
	CREATE TABLE IF NOT EXISTS Maps (
		MapID   BIGINT NOT NULL,
		PRIMARY KEY(MapID)
	);`,
		`
	CREATE TABLE IF NOT EXISTS Sequenced (
		MapID   BIGINT      NOT NULL,
		Epoch   INTEGER     NOT NULL,
		Data    BLOB(1024)  NOT NULL,
		PRIMARY KEY(MapID, Epoch),
		FOREIGN KEY(MapID) REFERENCES Maps(MapID) ON DELETE CASCADE
	);`,
	}
	// ErrNotSupported occurs when performing an operaion that has been disabled.
	ErrNotSupported = errors.New("operation not supported")
)

// Sequenced stores objects in a table.
type Sequenced struct {
	db *sql.DB
}

// New returns an object that can store sequenced items for multiple maps.
// mapID will be the only allowed mapID.
func New(db *sql.DB, mapID int64) (sequenced.Sequenced, error) {
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("No DB connection: %v", err)
	}

	if err := create(db); err != nil {
		return nil, err
	}
	if err := insertMapRow(db, mapID); err != nil {
		return nil, err
	}
	return &Sequenced{
		db: db,
	}, nil
}

// Create creates a new database.
func create(db *sql.DB) error {
	for _, stmt := range createStmt {
		_, err := db.Exec(stmt)
		if err != nil {
			return fmt.Errorf("Failed to create appender tables: %v", err)
		}
	}
	return nil
}

func insertMapRow(db *sql.DB, mapID int64) error {
	// Check if a map row does not exist for the same MapID.
	countStmt, err := db.Prepare(countMapRowExpr)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	defer countStmt.Close()
	var count int
	if err := countStmt.QueryRow(mapID).Scan(&count); err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	if count >= 1 {
		return nil
	}

	// Insert a map row if it does not exist already.
	insertStmt, err := db.Prepare(insertMapRowExpr)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	defer insertStmt.Close()
	_, err = insertStmt.Exec(mapID)
	if err != nil {
		return fmt.Errorf("insertMapRow(): %v", err)
	}
	return nil
}

// Append adds an object to the append-only data structure.
func (s *Sequenced) Write(txn transaction.Txn, mapID, epoch int64, obj interface{}) error {
	var data bytes.Buffer
	if err := gob.NewEncoder(&data).Encode(obj); err != nil {
		return err
	}
	writeStmt, err := txn.Prepare(insertExpr)
	if err != nil {
		return fmt.Errorf("DB save failure: %v", err)
	}
	defer writeStmt.Close()
	_, err = writeStmt.Exec(mapID, epoch, data.Bytes())
	if err != nil {
		return fmt.Errorf("DB commit failure: %v", err)
	}
	return nil
}

// Read retrieves a specific object for a map's epoch.
func (s *Sequenced) Read(txn transaction.Txn, mapID, epoch int64, obj interface{}) error {
	readStmt, err := txn.Prepare(readExpr)
	if err != nil {
		return err
	}
	defer readStmt.Close()

	var data []byte
	if err := readStmt.QueryRow(mapID, epoch).Scan(&data); err != nil {
		return err
	}

	err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(obj)
	if err != nil {
		return err
	}
	return nil
}

// Latest returns the latest object.
func (s *Sequenced) Latest(txn transaction.Txn, mapID int64, obj interface{}) (int64, error) {
	readStmt, err := txn.Prepare(latestExpr)
	if err != nil {
		return 0, err
	}
	defer readStmt.Close()

	var epoch int64
	var data []byte
	if err := readStmt.QueryRow(mapID).Scan(&epoch, &data); err != nil {
		return 0, err
	}
	err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(obj)
	if err != nil {
		return 0, err
	}
	return epoch, nil
}
