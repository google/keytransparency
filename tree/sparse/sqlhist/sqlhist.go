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

// Package sqlhist implements a temporal sparse merkle tree using SQL.
// Each epoch has its own sparse tree. By default, each new epoch is equal to
// the contents of the previous epoch.
package sqlhist

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"log"

	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/tree/sparse"
	"golang.org/x/net/context"
)

var (
	hasher      = sparse.Coniks
	errNilLeaf  = errors.New("Nil leaf")
	errIndexLen = errors.New("Index len != 32")
)

const (
	maxDepth = sparse.IndexLen
	size     = sparse.HashSize
	readExpr = `
	SELECT Value FROM Nodes
	WHERE MapId = $1 AND NodeId = $2 and Version <= $3
	ORDER BY Version DESC LIMIT 1;`
	queueExpr = `
	INSERT INTO Leaves (MapId, LeafId, Version, Data)
	VALUES ($1, $2, $3, $4);`
	pendingLeafsExpr = `
	SELECT LeafId, Version, Data FROM Leaves 
	WHERE MapId = $1 AND Version >= $2;`
	setNodeExpr = `
	INSERT OR REPLACE INTO Nodes (MapId, NodeId, Version, Value)
	VALUES ($1, $2, $3, $4);`
	mapRowExpr    = `INSERT OR IGNORE INTO Maps (MapId) VALUES ($1);`
	readEpochExpr = `SELECT MAX(Version) FROM Leaves WHERE MapId = $1;`
)

type Map struct {
	mapID []byte
	db    *sql.DB
	epoch int64 // The currently valid epoch. Insert at epoch+1.
}

func New(db *sql.DB, mapID string) *Map {
	if err := db.Ping(); err != nil {
		log.Fatalf("No DB connection: %v", err)
	}

	m := &Map{
		mapID: []byte(mapID),
		db:    db,
	}
	m.create()
	m.insertMapRow()
	m.insertFirstRoot()
	m.epoch = m.readEpoch()
	return m
}

// Epoch returns the current epoch of the merkle tree.
func (m *Map) Epoch() int64 {
	return m.epoch
}

// QueueLeaf should only be called by the sequencer.
func (m *Map) QueueLeaf(ctx context.Context, index, leaf []byte) error {
	if got, want := len(index), size; got != want {
		return errIndexLen
	}
	if leaf == nil {
		return errNilLeaf
	}

	// Write leaf nodes
	stmt, err := m.db.Prepare(queueExpr)
	if err != nil {
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(m.mapID, index, m.epoch+1, leaf)
	return err
}

type leafRow struct {
	index   []byte
	version int64
	data    []byte
}

// Commit takes all the Queued values since the last Commmit() and writes them.
// Commit is NOT multi-process safe. It should only be called from the sequencer.
func (m *Map) Commit() (int64, error) {
	// Get the list of pending leafs
	stmt, err := m.db.Prepare(pendingLeafsExpr)
	if err != nil {
		return m.epoch, err
	}
	defer stmt.Close()
	rows, err := stmt.Query(m.mapID, m.epoch+1)
	if err != nil {
		return m.epoch, err
	}
	leafRows := make([]leafRow, 0, 10)
	for rows.Next() {
		var r leafRow
		err = rows.Scan(&r.index, &r.version, &r.data)
		if err != nil {
			return m.epoch, err
		}
		leafRows = append(leafRows, r)
	}

	for _, r := range leafRows {
		if err := m.SetNodeAt(nil, r.index, maxDepth, r.data, m.epoch+1); err != nil {
			// Recovery from here would mean updating nodes that
			// didn't get included so that they would be included
			// in the next epoch.
			log.Fatalf("Failed to set node: %v", err)
		}
	}
	// TODO: Always update the root node.
	// TODO: Delete Map heads from this file.

	m.epoch++
	return m.epoch, nil
}

// ReadRootAt returns the value of the root node in a specific epoch.
func (m *Map) ReadRootAt(ctx context.Context, epoch int64) ([]byte, error) {
	stmt, err := m.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer stmt.Close()

	var value []byte
	rootID := m.nodeID("")
	if err := stmt.QueryRow(m.mapID, rootID, epoch).Scan(&value); err == sql.ErrNoRows {
		return nil, sql.ErrNoRows
	} else if err != nil {
		return nil, err
	}
	return value, nil
}

// ReadLeafAt returns the leaf value at epoch.
func (m *Map) ReadLeafAt(ctx context.Context, index []byte, epoch int64) ([]byte, error) {
	bindex := tree.BitString(index)
	readStmt, err := m.db.Prepare(readExpr)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()

	nodeID := m.nodeID(bindex)

	var value []byte
	if err = readStmt.QueryRow(m.mapID, nodeID, epoch).Scan(&value); err == sql.ErrNoRows {
		return nil, nil // Not found is not an error.
	} else if err != nil {
		return nil, err
	}
	return value, nil
}

// Neighbors returns the list of neighbors from the neighbor leaf to just below the root at epoch.
func (m *Map) NeighborsAt(ctx context.Context, index []byte, epoch int64) ([][]byte, error) {
	tx, err := m.db.Begin()
	if err != nil {
		return nil, err
	}
	nbrs, err := m.neighborsAt(tx, index, maxDepth, epoch)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	nbrs = compressNeighbors(nbrs, index, maxDepth)
	return nbrs, tx.Commit()
}

func (m *Map) neighborsAt(tx *sql.Tx, index []byte, depth int, epoch int64) ([][]byte, error) {
	bindex := tree.BitString(index)[:depth]
	neighborBIndexes := tree.Neighbors(bindex)
	neighborIDs := m.nodeIDs(neighborBIndexes)

	readStmt, err := tx.Prepare(readExpr)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	defer readStmt.Close()

	// Get neighbors.
	nbrValues := make([][]byte, len(neighborIDs))
	for i, nodeID := range neighborIDs {
		if err := readStmt.QueryRow(m.mapID, nodeID, epoch).Scan(&nbrValues[i]); err == sql.ErrNoRows {
			nbrValues[i] = hashEmpty(neighborBIndexes[i])
		} else if err != nil {
			tx.Rollback()
			return nil, err
		}
	}

	return nbrValues, nil
}
func compressNeighbors(neighbors [][]byte, index []byte, depth int) [][]byte {
	bindex := tree.BitString(index)[:depth]
	neighborBIndexes := tree.Neighbors(bindex)
	compressed := make([][]byte, len(neighbors))
	for i, v := range neighbors {
		// TODO: convert values to arrays rather than slices for comparison.
		if !bytes.Equal(v, hashEmpty(neighborBIndexes[i])) {
			compressed[i] = v
		}
	}
	return compressed
}

// SetNodeAt sets intermediate and leaf node values directly at epoch.
func (m *Map) SetNodeAt(ctx context.Context, index []byte, depth int, value []byte, epoch int64) error {
	if value == nil || len(value) == 0 {
		return nil
	}
	bindex := tree.BitString(index)[:depth]
	nodeBindexes := tree.Path(bindex)
	nodeIDs := m.nodeIDs(nodeBindexes)

	// Read the neighbor nodes
	// Set the node
	// Compute new values
	// Set those values.

	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	writeStmt, err := tx.Prepare(setNodeExpr)
	if err != nil {
		tx.Rollback()
		return err
	}
	defer writeStmt.Close()

	// Get neighbors.
	nbrValues, err := m.neighborsAt(tx, index, depth, epoch)
	if err != nil {
		tx.Rollback()
		return err
	}

	nodeValues := sparse.NodeValues(hasher, bindex, value, nbrValues)

	// Save new nodes.
	for i, nodeValue := range nodeValues {
		_, err = writeStmt.Exec(m.mapID, nodeIDs[i], epoch, nodeValue)
		if err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// Create creates a new database.
func (m *Map) create() {
	createStmt := `
	CREATE TABLE IF NOT EXISTS Maps (
		MapId	BLOB(32),
		PRIMARY KEY(MapID)
	);

	CREATE TABLE IF NOT EXISTS Leaves (
		MapId	BLOB(32) NOT NULL,
		LeafId	BLOB(32) NOT NULL,
		Version	INTEGER	 NOT NULL,
		Data	BLOB 	 NOT NULL,
		PRIMARY KEY(MapID, LeafId, Version),
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS Nodes (
		MapId	BLOB(32) NOT NULL,
		NodeId	BLOB(32) NOT NULL,
		Version	INTEGER  NOT NULL,
		Value	BLOB(32) NOT NULL,
		PRIMARY KEY(MapId, NodeId, Version),
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS MapHeads (
		MapId	BLOB(32) NOT NULL,
		Version INTEGER  NOT NULL,
		Timestamp TIMESTAMP NOT NULL,
		Value	Blob(32) NOT NULL,
		PRIMARY KEY(MapId, Version),  
		FOREIGN KEY(MapId) REFERENCES Maps(MapId) ON DELETE CASCADE
	)
	`
	_, err := m.db.Exec(createStmt)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
}

func (m *Map) insertMapRow() {
	stmt, err := m.db.Prepare(mapRowExpr)
	if err != nil {
		log.Fatalf("insertMapRow(): %v", err)
	}
	defer stmt.Close()
	_, err = stmt.Exec(m.mapID)
	if err != nil {
		log.Fatalf("insertMapRow(): %v", err)
	}
}

func (m *Map) insertFirstRoot() {
	rootID := m.nodeID("")
	nodeValue := hashEmpty("")
	writeStmt, err := m.db.Prepare(setNodeExpr)
	if err != nil {
		log.Fatalf("insertFirstRoot(): %v", err)
	}
	defer writeStmt.Close()
	_, err = writeStmt.Exec(m.mapID, rootID, -1, nodeValue)
	if err != nil {
		log.Fatalf("insertFirstRoot(): %v", err)
	}
}

func (m *Map) readEpoch() int64 {
	stmt, err := m.db.Prepare(readEpochExpr)
	if err != nil {
		log.Fatalf("readEpoch(): %v", err)
	}
	defer stmt.Close()
	var epoch sql.NullInt64
	if err := stmt.QueryRow(m.mapID).Scan(&epoch); err != nil {
		log.Fatalf("Error reading epoch: %v", err)
	}
	if !epoch.Valid {
		return -1
	}
	return epoch.Int64
}

// Converts a list of bit strings into their node IDs.
func (m *Map) nodeIDs(bindexes []string) [][]byte {
	nodes := make([][]byte, len(bindexes))
	for i, bindex := range bindexes {
		nodes[i] = m.nodeID(bindex)
	}
	return nodes
}

// nodeID computes the location of a node, given its bit string index.
func (m *Map) nodeID(bindex string) []byte {
	h := sha256.New()
	h.Write(m.mapID)
	h.Write([]byte{0})
	h.Write([]byte(bindex))
	return h.Sum(nil)
}

// PrefixLen returns the index of the last non-zero item in the list
func PrefixLen(nodes [][]byte) int {
	// Iterate over the nodes from leaf to root.
	for i, v := range nodes {
		if v != nil {
			// return the first non-empty node.
			return len(nodes) - i
		}
	}
	return 0
}

func hashEmpty(bindex string) []byte {
	return hasher.HashEmpty(tree.InvertBitString(bindex))
}
