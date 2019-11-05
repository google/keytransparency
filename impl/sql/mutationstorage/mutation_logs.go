// Copyright 2018 Google Inc. All Rights Reserved.
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

package mutationstorage

import (
	"context"
	"database/sql"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/mutator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// SetWritable enables or disables new writes from going to logID.
func (m *Mutations) SetWritable(ctx context.Context, directoryID string, logID int64, enabled bool) error {
	result, err := m.db.ExecContext(ctx,
		`UPDATE Logs SET Enabled = ? WHERE DirectoryID = ? AND LogID = ?;`,
		enabled, directoryID, logID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return status.Errorf(codes.NotFound, "log %d not found for directory %v", logID, directoryID)
	}
	return err
}

// AddLogs creates and adds new logs for writing to a directory.
func (m *Mutations) AddLogs(ctx context.Context, directoryID string, logIDs ...int64) error {
	glog.Infof("mutationstorage: AddLog(%v, %v)", directoryID, logIDs)
	for _, logID := range logIDs {
		// TODO(gdbelvin): Use INSERT IGNORE to allow this function to be retried.
		// TODO(gdbelvin): Migrate to a MySQL Docker image for unit tests.
		// MySQL and SQLite do not have the same syntax for INSERT IGNORE.
		if _, err := m.db.ExecContext(ctx,
			`INSERT INTO Logs (DirectoryID, LogID, Enabled)  Values(?, ?, ?);`,
			directoryID, logID, true); err != nil {
			return err
		}
	}
	return nil
}

// Send writes mutations to the leading edge (by sequence number) of the mutations table.
// Returns the logID/watermark pair that was written, or nil if nothing was written.
// TODO(gbelvin): Make updates a slice.
func (m *Mutations) Send(ctx context.Context, directoryID string, logID int64, updates ...*pb.EntryUpdate) (int64, time.Time, error) {
	glog.Infof("mutationstorage: Send(%v, <mutation>)", directoryID)
	if len(updates) == 0 {
		return 0, time.Time{}, nil
	}
	updateData := make([][]byte, 0, len(updates))
	for _, u := range updates {
		data, err := proto.Marshal(u)
		if err != nil {
			return 0, time.Time{}, err
		}
		updateData = append(updateData, data)
	}
	// TODO(gbelvin): Implement retry with backoff for retryable errors if
	// we get timestamp contention.
	ts := time.Now()
	if err := m.send(ctx, ts, directoryID, logID, updateData...); err != nil {
		return 0, time.Time{}, err
	}
	return logID, ts, nil
}

// ListLogs returns a list of all logs for directoryID, optionally filtered for writable logs.
func (m *Mutations) ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error) {
	var query string
	if writable {
		query = `SELECT LogID from Logs WHERE DirectoryID = ? AND Enabled = True;`
	} else {
		query = `SELECT LogID from Logs WHERE DirectoryID = ?;`
	}
	var logIDs []int64
	rows, err := m.db.QueryContext(ctx, query, directoryID)
	if err != nil {
		return nil, err
	}

	defer rows.Close()
	for rows.Next() {
		var logID int64
		if err := rows.Scan(&logID); err != nil {
			return nil, err
		}
		logIDs = append(logIDs, logID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(logIDs) == 0 {
		return nil, status.Errorf(codes.NotFound, "no log found for directory %v", directoryID)
	}
	return logIDs, nil
}

// ts must be greater than all other timestamps currently recorded for directoryID.
func (m *Mutations) send(ctx context.Context, ts time.Time, directoryID string,
	logID int64, mData ...[]byte) (ret error) {
	tx, err := m.db.BeginTx(ctx,
		&sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return err
	}
	defer func() {
		if ret != nil {
			if err := tx.Rollback(); err != nil {
				ret = status.Errorf(codes.Internal, "%v, and could not rollback: %v", ret, err)
			}
		}
	}()

	var maxTime sql.NullTime
	if err := tx.QueryRowContext(ctx,
		`SELECT MAX(Time) FROM Queue WHERE DirectoryID = ? AND LogID = ?;`,
		directoryID, logID).Scan(&maxTime); err != nil {
		return status.Errorf(codes.Internal, "could not find max timestamp: %v", err)
	}

	// The Timestamp column has a maximum fidelity of microseconds.
	// See https://dev.mysql.com/doc/refman/8.0/en/fractional-seconds.html
	ts = ts.Truncate(time.Microsecond)
	if !ts.After(maxTime.Time) {
		return status.Errorf(codes.Aborted,
			"current timestamp: %v, want > max-timestamp of queued mutations: %v", ts, maxTime)
	}

	for i, data := range mData {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO Queue (DirectoryID, LogID, Time, LocalID, Mutation) VALUES (?, ?, ?, ?, ?);`,
			directoryID, logID, ts, i, data); err != nil {
			return status.Errorf(codes.Internal, "failed inserting into queue: %v", err)
		}
	}
	return tx.Commit()
}

// HighWatermark returns the highest watermark +1 in logID that is less than or
// equal to batchSize items greater than start.
func (m *Mutations) HighWatermark(ctx context.Context, directoryID string, logID int64,
	start time.Time, batchSize int32) (int32, time.Time, error) {
	var count int32
	var high sql.NullTime
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(T1.Time) FROM
		(
			SELECT Q.Time FROM Queue as Q
			WHERE Q.DirectoryID = ? AND Q.LogID = ? AND Q.Time >= ?
			ORDER BY Q.Time ASC
			LIMIT ?
		) AS T1`,
		directoryID, logID, start, batchSize).
		Scan(&count, &high); err != nil {
		return 0, start, err
	}
	if count == 0 {
		// When there are no rows, return the start time as the highest timestamp.
		return 0, start, nil
	}
	return count, high.Time.Add(1 * time.Microsecond), nil
}

// ReadLog reads all mutations in logID between [low, high).
// ReadLog may return more rows than batchSize in order to fetch all the rows at a particular timestamp.
func (m *Mutations) ReadLog(ctx context.Context, directoryID string,
	logID int64, low, high time.Time, batchSize int32) ([]*mutator.LogMessage, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT Time, LocalID, Mutation FROM Queue
		WHERE DirectoryID = ? AND LogID = ? AND Time >= ? AND Time < ?
		ORDER BY Time, LocalID ASC
		LIMIT ?;`,
		directoryID, logID, low, high, batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs, err := readQueueMessages(rows)
	if err != nil {
		return nil, err
	}

	// Read the rest of the LocalIDs in the last row.
	if len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		restRows, err := m.db.QueryContext(ctx,
			`SELECT Time, LocalID, Mutation FROM Queue
			WHERE DirectoryID = ? AND LogID = ? AND Time = ? AND LocalID > ?
			ORDER BY LocalID ASC;`,
			directoryID, logID, last.ID, last.LocalID)
		if err != nil {
			return nil, err
		}
		defer restRows.Close()
		rest, err := readQueueMessages(restRows)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, rest...)
	}

	return msgs, nil
}

func readQueueMessages(rows *sql.Rows) ([]*mutator.LogMessage, error) {
	results := make([]*mutator.LogMessage, 0)
	for rows.Next() {
		var timestamp time.Time
		var localID int64
		var mData []byte
		if err := rows.Scan(&timestamp, &localID, &mData); err != nil {
			return nil, err
		}
		entryUpdate := new(pb.EntryUpdate)
		if err := proto.Unmarshal(mData, entryUpdate); err != nil {
			return nil, err
		}
		results = append(results, &mutator.LogMessage{
			ID:        timestamp,
			LocalID:   localID,
			Mutation:  entryUpdate.Mutation,
			ExtraData: entryUpdate.Committed,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
