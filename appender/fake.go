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

package appender

import (
	"database/sql"
	"log"

	"golang.org/x/net/context"
)

// Fake is a noop append-only data structure.
// Especially useful for offline testing.
type Fake struct {
	mapID []byte
	db    *sql.DB
}

// NewFake creates a fake append-only client.  For testing purposes only.
func NewFake(db *sql.DB, mapID, logURL string) *Fake {
	if err := db.Ping(); err != nil {
		log.Fatalf("No DB connection: %v", err)
	}

	a := &Fake{
		mapID: []byte(mapID),
		db:    db,
	}

	// Create tables.
	_, err := db.Exec(createExpr)
	if err != nil {
		log.Fatalf("Failed to create appender tables: %v", err)
	}
	a.insertMapRow()
	return a
}

func (a *Fake) insertMapRow() {
	stmt, err := a.db.Prepare(mapRowExpr)
	if err != nil {
		log.Fatalf("Failed preparing mapID insert statement: %v", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(a.mapID)
	if err != nil {
		log.Fatalf("Failed executing mapID insert: %v", err)
	}
}

// Append is a noop.
func (a *Fake) Append(ctx context.Context, epoch int64, data []byte) error {
	writeStmt, err := a.db.Prepare(insertExpr)
	if err != nil {
		log.Printf("CT: DB save failure: %v", err)
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.Exec(a.mapID, epoch, data, []byte("fakesct"))
	if err != nil {
		log.Printf("CT: DB commit failure: %v", err)
		return err
	}
	return nil
}

// Epoch is a noop.
func (a *Fake) Epoch(ctx context.Context, epoch int64) ([]byte, []byte, error) {
	readStmt, err := a.db.Prepare(readExpr)
	if err != nil {
		return nil, nil, err
	}
	defer readStmt.Close()

	var data, sct []byte
	if err := readStmt.QueryRow(a.mapID, epoch).Scan(&data, &sct); err != nil {
		return nil, nil, err
	}
	return data, sct, nil
}

// Latest is a noop.
func (a *Fake) Latest(ctx context.Context) (int64, []byte, []byte, error) {
	readStmt, err := a.db.Prepare(latestExpr)
	if err != nil {
		return 0, nil, nil, err
	}
	defer readStmt.Close()

	var epoch int64
	var data, sct []byte
	if err := readStmt.QueryRow(a.mapID).Scan(&epoch, &data, &sct); err != nil {
		return 0, nil, nil, err
	}
	return epoch, data, sct, nil
}
