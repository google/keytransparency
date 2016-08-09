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
	"bytes"
	"database/sql"
	"encoding/gob"
	"errors"
	"log"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/client"
	"golang.org/x/net/context"
)

const (
	createExpr = `
	CREATE TABLE IF NOT EXISTS Maps (
		MapId	BLOB(32),
		PRIMARY KEY(MapID)
	);

	CREATE TABLE IF NOT EXISTS SMH (
		MapId	BLOB(32) NOT NULL,
		Epoch 	INTEGER NOT NULL,
		Data	BLOB(1024) NOT NULL,
		SCT	BLOB(1024) NOT NULL,
		PRIMARY KEY(MapID, Epoch),
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	);`
	mapRowExpr = `
	INSERT OR IGNORE INTO Maps (MapId) VALUES ($1);`
	insertExpr = `
	INSERT INTO SMH (MapId, Epoch, Data, SCT)
	VALUES ($1, $2, $3, $4);`
	readExpr = `
	SELECT Data, SCT FROM SMH
	WHERE MapId = $1 AND Epoch = $2;`
	latestExpr = `
	SELECT Epoch, Data, SCT FROM SMH
	WHERE MapId = $1 
	ORDER BY Epoch DESC LIMIT 1;`
)

var (
	// ErrNotSupported occurs when performing an operaion that has been disabled.
	ErrNotSupported = errors.New("operation not supported")
)

// CTAppender stores objects in a local table and submits them to an append-only log.
type CTAppender struct {
	mapID []byte
	db    *sql.DB
	ctlog *client.LogClient
	send  bool
	save  bool
}

// New creates a new client to an append-only data structure: Certificate Transparency.
func New(db *sql.DB, mapID, logURL string) *CTAppender {
	a := &CTAppender{
		mapID: []byte(mapID),
		db:    db,
		save:  db != nil,
		send:  logURL != "",
	}

	if a.save {
		if err := db.Ping(); err != nil {
			log.Fatalf("No DB connection: %v", err)
		}

		// Create tables.
		_, err := db.Exec(createExpr)
		if err != nil {
			log.Fatalf("Failed to create appender tables: %v", err)
		}
		a.insertMapRow()
	}
	if a.send {
		a.ctlog = client.New(logURL, nil)
		// Verify logURL.
		if _, err := a.ctlog.GetSTH(); err != nil {
			log.Fatalf("Failed to ping CT server with GetSTH: %v", err)
		}
	}
	return a
}

func (a *CTAppender) insertMapRow() {
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

// Append adds an object to the append-only data structure.
func (a *CTAppender) Append(ctx context.Context, epoch int64, obj interface{}) error {
	if a.send {
		sct, err := a.ctlog.AddJSON(obj)
		if err != nil {
			log.Printf("CT: Submission failure: %v", err)
			return err
		}
		if a.save {
			b, err := ct.SerializeSCT(*sct)
			if err != nil {
				log.Printf("CT: Serialization failure: %v", err)
				return err
			}
			var data bytes.Buffer
			if err := gob.NewEncoder(&data).Encode(obj); err != nil {
				return err
			}
			writeStmt, err := a.db.Prepare(insertExpr)
			if err != nil {
				log.Printf("CT: DB save failure: %v", err)
				return err
			}
			defer writeStmt.Close()
			_, err = writeStmt.Exec(a.mapID, epoch, data.Bytes(), b)
			if err != nil {
				log.Printf("CT: DB commit failure: %v", err)
				return err
			}
		}
	}
	return nil
}

// Epoch retrieves a specific object.
// Returns data and a serialized ct.SignedCertificateTimestamp
func (a *CTAppender) Epoch(ctx context.Context, epoch int64, obj interface{}) ([]byte, error) {
	if !a.save {
		return nil, ErrNotSupported
	}
	readStmt, err := a.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()

	var data, sct []byte
	if err := readStmt.QueryRow(a.mapID, epoch).Scan(&data, &sct); err != nil {
		return nil, err
	}

	err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(obj)
	return sct, err
}

// Latest returns the latest object.
// Returns epoch, data, and a serialized ct.SignedCertificateTimestamp
func (a *CTAppender) Latest(ctx context.Context, obj interface{}) (int64, []byte, error) {
	if !a.save {
		return 0, nil, ErrNotSupported
	}
	readStmt, err := a.db.Prepare(latestExpr)
	if err != nil {
		return 0, nil, err
	}
	defer readStmt.Close()

	var epoch int64
	var data, sct []byte
	if err := readStmt.QueryRow(a.mapID).Scan(&epoch, &data, &sct); err != nil {
		return 0, nil, err
	}
	err = gob.NewDecoder(bytes.NewBuffer(data)).Decode(obj)
	return epoch, sct, err
}
