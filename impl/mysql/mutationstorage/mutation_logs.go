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
	"fmt"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/internal/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	ktsql "github.com/google/keytransparency/impl/mysql"
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

// SendBatch writes mutations to the leading edge (by sequence number) of the mutations table.
// Returns the logID/watermark pair that was written, or nil if nothing was written.
func (m *Mutations) SendBatch(ctx context.Context, directoryID string, logID int64, batch []*pb.EntryUpdate) (water.Mark, error) {
	glog.Infof("mutationstorage: SendBatch(%v, <mutation>)", directoryID)
	if len(batch) == 0 {
		return water.Mark{}, nil
	}
	updateData := make([][]byte, 0, len(batch))
	for _, u := range batch {
		data, err := proto.Marshal(u)
		if err != nil {
			return water.Mark{}, err
		}
		updateData = append(updateData, data)
	}

	b := backoff.Backoff{Min: 10 * time.Millisecond, Max: time.Second, Factor: 1.2, Jitter: true}
	var wm water.Mark
	if err := b.Retry(ctx, func() error {
		wm = water.NewMark(uint64(time.Duration(time.Now().UnixNano()) * time.Nanosecond / time.Microsecond))
		err := m.send(ctx, wm, directoryID, logID, updateData...)
		if ktsql.IsDeadlock(err) {
			return backoff.RetriableErrorf("send failed: %w", err)
		}
		return err
	}); err != nil {
		return water.Mark{}, err
	}
	return wm, nil
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
		return nil, fmt.Errorf("query logs: %w", err)
	}

	defer rows.Close()
	for rows.Next() {
		var logID int64
		if err := rows.Scan(&logID); err != nil {
			return nil, fmt.Errorf("rows.Scan(): %w", err)
		}
		logIDs = append(logIDs, logID)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("rows.Err(): %w", err)
	}
	if len(logIDs) == 0 {
		return nil, status.Errorf(codes.NotFound, "no log found for directory %v", directoryID)
	}
	return logIDs, nil
}

// ts must be greater than all other timestamps currently recorded for directoryID.
func (m *Mutations) send(ctx context.Context, wm water.Mark, directoryID string,
	logID int64, mData ...[]byte) (ret error) {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		if ret != nil {
			if err := tx.Rollback(); err != nil {
				ret = fmt.Errorf("%v, and could not rollback: %w", ret, err)
			}
		}
	}()

	var maxTimestamp int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(TimeMicros), 0) FROM Queue WHERE DirectoryID = ? AND LogID = ?;`,
		directoryID, logID).Scan(&maxTimestamp); err != nil {
		return fmt.Errorf("could not find max timestamp: %w", err)
	}

	if wm.Value() <= uint64(maxTimestamp) {
		return status.Errorf(codes.Aborted,
			"current timestamp: %v, want > max-timestamp of queued mutations: %v", wm, maxTimestamp)
	}

	for i, data := range mData {
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO Queue (DirectoryID, LogID, TimeMicros, LocalID, Mutation) VALUES (?, ?, ?, ?, ?);`,
			directoryID, logID, wm.Value(), i, data); err != nil {
			return fmt.Errorf("failed inserting into queue: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}

// HighWatermark returns the highest watermark +1 in logID that is less than or
// equal to batchSize items greater than start.
func (m *Mutations) HighWatermark(ctx context.Context, directoryID string, logID int64,
	start water.Mark, batchSize int32) (int32, water.Mark, error) {
	var count int32
	var highTimestamp int64
	if err := m.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MAX(T1.TimeMicros), 0) FROM
		(
			SELECT Q.TimeMicros FROM Queue as Q
			WHERE Q.DirectoryID = ? AND Q.LogID = ? AND Q.TimeMicros >= ?
			ORDER BY Q.TimeMicros ASC
			LIMIT ?
		) AS T1`,
		directoryID, logID, start.Value(), batchSize).
		Scan(&count, &highTimestamp); err != nil {
		return 0, start, err
	}
	if count == 0 {
		// When there are no rows, return the start time as the highest timestamp.
		return 0, start, nil
	}
	return count, water.NewMark(uint64(highTimestamp) + 1), nil
}

// ReadLog reads all mutations in logID between [low, high).
// ReadLog may return more rows than batchSize in order to fetch all the rows at a particular timestamp.
func (m *Mutations) ReadLog(ctx context.Context, directoryID string,
	logID int64, low, high water.Mark, batchSize int32) ([]*mutator.LogMessage, error) {
	// Advance the low and high marks to the next highest quantum to preserve read semantics.
	rows, err := m.db.QueryContext(ctx,
		`SELECT TimeMicros, LocalID, Mutation FROM Queue
		WHERE DirectoryID = ? AND LogID = ? AND TimeMicros >= ? AND TimeMicros < ?
		ORDER BY TimeMicros, LocalID ASC
		LIMIT ?;`,
		directoryID, logID, low.Value(), high.Value(), batchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	msgs, err := readQueueMessages(rows, logID)
	if err != nil {
		return nil, err
	}

	// Read the rest of the LocalIDs in the last row.
	if len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		restRows, err := m.db.QueryContext(ctx,
			`SELECT TimeMicros, LocalID, Mutation FROM Queue
			WHERE DirectoryID = ? AND LogID = ? AND TimeMicros = ? AND LocalID > ?
			ORDER BY LocalID ASC;`,
			directoryID, logID, last.ID.Value(), last.LocalID)
		if err != nil {
			return nil, err
		}
		defer restRows.Close()
		rest, err := readQueueMessages(restRows, logID)
		if err != nil {
			return nil, err
		}
		msgs = append(msgs, rest...)
	}

	return msgs, nil
}

func readQueueMessages(rows *sql.Rows, logID int64) ([]*mutator.LogMessage, error) {
	results := make([]*mutator.LogMessage, 0)
	for rows.Next() {
		var timestamp int64
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
			LogID:     logID,
			ID:        water.NewMark(uint64(timestamp)),
			LocalID:   localID,
			CreatedAt: time.Unix(0, int64(time.Duration(timestamp)*time.Microsecond/time.Nanosecond)),
			Mutation:  entryUpdate.Mutation,
			ExtraData: entryUpdate.Committed,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}
