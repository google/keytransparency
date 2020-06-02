// Copyright 2020 Google Inc. All Rights Reserved.
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

// Package mutations stores mutations by timestamp.
package mutations

import (
	"context"
	"fmt"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/water"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// readStaleness should be large enough for spanner to read from replicas.
const readStaleness = 1 * time.Second
const mutTable = "Mutations"
const logTable = "LogStatus"
const tsRes = 1 * time.Microsecond // Spanner has a 1 microsecond timestamp resolution.

func markToTime(w water.Mark) time.Time {
	nanos := int64(w.Value()) * int64(tsRes)
	return time.Unix(0, nanos)
}
func timeToMark(t time.Time) water.Mark {
	m := t.Truncate(tsRes)
	v := uint64(m.UnixNano()) / uint64(tsRes)
	return water.NewMark(v)
}

// Table implements a queue of mutations.
type Table struct {
	client *spanner.Client
}

// LogStatusCols are the columns in the LogStatus table.
type LogStatusCols struct {
	DirectoryID string
	LogID       int64
	WriteToLog  bool
}

// New returns a new Table object.
func New(client *spanner.Client) *Table {
	return &Table{client: client}
}

// SetWritable enables or disables new writes from going to logID.
func (t *Table) SetWritable(ctx context.Context, directoryID string, logID int64, enabled bool) error {
	rtx := t.client.Single()
	defer rtx.Close()

	m, err := spanner.UpdateStruct(logTable, LogStatusCols{
		DirectoryID: directoryID,
		LogID:       logID,
		WriteToLog:  enabled,
	})
	if err != nil {
		return err
	}
	_, err = t.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// AddLogs adds the logIDs to the list of active logs to send mutations to, and read mutations from.
// If directoryID and logID already exist, they will be marked as writable.
func (t *Table) AddLogs(ctx context.Context, directoryID string, logIDs ...int64) error {
	if len(logIDs) == 0 {
		return fmt.Errorf("no logs to add")
	}

	rtx := t.client.Single()
	defer rtx.Close()

	mutations := make([]*spanner.Mutation, 0, len(logIDs))
	for _, logID := range logIDs {
		// Ignore already exists errors so this method can be retried.
		m, err := spanner.InsertOrUpdateStruct(logTable, LogStatusCols{
			DirectoryID: directoryID,
			LogID:       logID,
			WriteToLog:  true,
		})
		if err != nil {
			return err
		}
		mutations = append(mutations, m)
	}
	_, err := t.client.Apply(ctx, mutations)
	return err
}

// ListLogs returns the mutation logIDs assocciated with directoryID.
// If writable is true, the list is filtered to only contain writable logs.
// Returns codes.NotFound if the list is empty.
func (t *Table) ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error) {
	var stmt spanner.Statement
	if writable {
		stmt = spanner.NewStatement(
			`SELECT LogID FROM LogStatus WHERE DirectoryID = @directory_id AND WriteToLog = TRUE`)
	} else {
		stmt = spanner.NewStatement(
			`SELECT LogID FROM LogStatus WHERE DirectoryID = @directory_id`)
	}
	stmt.Params["directory_id"] = directoryID
	var logIDs []int64
	rtx := t.client.Single().WithTimestampBound(spanner.MaxStaleness(readStaleness))
	defer rtx.Close()
	if err := rtx.Query(ctx, stmt).Do(
		func(row *spanner.Row) error {
			var logID int64
			if err := row.Columns(&logID); err != nil {
				return err
			}
			logIDs = append(logIDs, logID)
			return nil
		}); err != nil {
		return nil, err
	}
	if len(logIDs) == 0 {
		return nil, status.Errorf(codes.NotFound, "not found")
	}
	return logIDs, nil
}

// Send submits a batch of items to the queue and returns the commit timestamp.
func (t *Table) SendBatch(ctx context.Context, directoryID string, logID int64, batch []*pb.EntryUpdate) (water.Mark, error) {
	if len(batch) == 0 {
		return water.Mark{}, fmt.Errorf("no entries to send")
	}
	type Cols struct {
		DirectoryID string
		LogID       int64
		Timestamp   time.Time
		LocalID     int64
		Mutation    []byte
	}
	ms := make([]*spanner.Mutation, 0, len(batch))
	for i, e := range batch {
		mBytes, err := proto.Marshal(e)
		if err != nil {
			return water.Mark{}, err
		}
		m, err := spanner.InsertStruct(mutTable, Cols{
			DirectoryID: directoryID,
			LogID:       logID,
			Timestamp:   spanner.CommitTimestamp,
			LocalID:     int64(i),
			Mutation:    mBytes,
		})
		if err != nil {
			return water.Mark{}, err
		}
		ms = append(ms, m)
	}

	commitTimestamp, err := t.client.ReadWriteTransaction(ctx,
		func(_ context.Context, txn *spanner.ReadWriteTransaction) error {
			return txn.BufferWrite(ms)
		})
	if err != nil {
		return water.Mark{}, err
	}
	return timeToMark(commitTimestamp), nil
}

// HighWatermark returns the number of items and the highest timestamp
// (exclusive) up to limit items after start (inclusive).
// Because batches (items that have the same timestamp) can contain more than one item, count may exceed limit.
func (t *Table) HighWatermark(ctx context.Context, directoryID string, logID int64, start water.Mark, limit int32) (count int32, high water.Mark, err error) {
	// TODO: Replace with MAX(Timestamp) when spansql supports aggregate operators.
	stmt := spanner.NewStatement(`
	SELECT
	   Timestamp
	FROM
	   Mutations
	WHERE
	   DirectoryID = @directoryID AND
	   LogID = @logID AND
	   Timestamp >= @start
	ORDER BY Timestamp
	LIMIT @limit`)
	stmt.Params["directoryID"] = directoryID
	stmt.Params["logID"] = logID
	stmt.Params["start"] = markToTime(start)
	stmt.Params["limit"] = int64(limit)

	var cnt int64
	var max time.Time
	rtx := t.client.Single().WithTimestampBound(spanner.MaxStaleness(readStaleness))
	defer rtx.Close()
	if err := rtx.Query(ctx, stmt).Do(
		func(row *spanner.Row) error {
			cnt++
			var watermark time.Time
			if err := row.Column(0, &watermark); err != nil {
				return err
			}
			if watermark.After(max) {
				max = watermark
			}
			return nil
		}); err != nil {
		return 0, water.Mark{}, err
	}
	if cnt == 0 {
		// When there are no rows, return the start time as the highest timestamp.
		return 0, start, nil
	}
	return int32(cnt), timeToMark(max).Add(1), nil
}

// ReadLog reads all mutations between [low, high).
// If limit is used, ReadLog ensures that complete batches are returned, which could slightly exceed limit.
func (t *Table) ReadLog(ctx context.Context, directoryID string, logID int64, low, high water.Mark,
	limit int32) ([]*mutator.LogMessage, error) {
	if high.Value() == 0 || limit == 0 {
		return []*mutator.LogMessage{}, nil
	}

	msgs := make([]*mutator.LogMessage, 0, limit)
	rtx := t.client.Single().WithTimestampBound(spanner.MinReadTimestamp(markToTime(high)))
	defer rtx.Close()
	if err := rtx.ReadWithOptions(ctx, mutTable,
		spanner.KeyRange{
			Kind:  spanner.ClosedOpen,
			Start: spanner.Key{directoryID, logID, markToTime(low), 0},
			End:   spanner.Key{directoryID, logID, markToTime(high), 0},
		},
		[]string{"Timestamp", "LocalID", "Mutation"},
		&spanner.ReadOptions{Limit: int(limit)},
	).Do(func(r *spanner.Row) error {
		msg, err := unmarshalRow(r, logID)
		if err != nil {
			return err
		}
		msgs = append(msgs, msg)
		return nil
	}); err != nil {
		return nil, err
	}
	var maxTs water.Mark
	var maxLocal int64
	if len(msgs) == int(limit) {
		// There might be more messages in this batch to read.
		for _, m := range msgs {
			if m.ID.Value() > maxTs.Value() {
				maxTs = m.ID
				maxLocal = 0
			}
			if m.ID.Value() == maxTs.Value() &&
				m.LocalID > maxLocal {
				maxLocal = m.LocalID
			}
		}
		rtx := t.client.Single().WithTimestampBound(spanner.MinReadTimestamp(markToTime(high)))
		defer rtx.Close()
		if err := rtx.Read(ctx, mutTable,
			spanner.KeyRange{
				Kind:  spanner.OpenOpen,
				Start: spanner.Key{directoryID, logID, markToTime(maxTs), maxLocal},
				End:   spanner.Key{directoryID, logID, markToTime(maxTs.Add(1)), 0},
			},
			[]string{"Timestamp", "LocalID", "Mutation"},
		).Do(func(r *spanner.Row) error {
			msg, err := unmarshalRow(r, logID)
			if err != nil {
				return err
			}
			msgs = append(msgs, msg)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return msgs, nil
}

func unmarshalRow(r *spanner.Row, logID int64) (*mutator.LogMessage, error) {
	type Cols struct {
		Timestamp time.Time
		LocalID   int64
		Mutation  []byte
	}
	var cols Cols
	if err := r.ToStruct(&cols); err != nil {
		return nil, err
	}
	var mutation pb.EntryUpdate
	if err := proto.Unmarshal(cols.Mutation, &mutation); err != nil {
		return nil, err
	}
	msg := &mutator.LogMessage{
		LogID: logID,
		// ID must be monotonically increasing and is set via the commit timestamp for monotonicity.
		ID: timeToMark(cols.Timestamp),
		// ID + LocalID must be unique per mutation and is part of the primary key for uniquness.
		LocalID:   cols.LocalID,
		CreatedAt: cols.Timestamp,
		Mutation:  mutation.Mutation,
		ExtraData: mutation.Committed,
	}
	return msg, nil
}
