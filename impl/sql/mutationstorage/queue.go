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
	"math/rand"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/keytransparency/core/mutator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// AddShards creates and adds new shards for queue writing to a domain.
func (m *Mutations) AddShards(ctx context.Context, domainID string, shardIDs ...int64) error {
	glog.Infof("mutationstorage: AddShard(%v, %v)", domainID, shardIDs)
	for _, shardID := range shardIDs {
		// TODO(gdbelvin): Use INSERT IGNORE to allow this function to be retried.
		// TODO(gdbelvin): Migrate to a MySQL Docker image for unit tests.
		// MySQL and SQLite do not have the same syntax for INSERT IGNORE.
		if _, err := m.db.ExecContext(ctx,
			`INSERT INTO Shards (DomainID, ShardID, Enabled)  Values(?, ?, ?);`,
			domainID, shardID, true); err != nil {
			return err
		}
	}
	return nil
}

// Send writes mutations to the leading edge (by sequence number) of the mutations table.
func (m *Mutations) Send(ctx context.Context, domainID string, update *pb.EntryUpdate) error {
	glog.Infof("mutationstorage: Send(%v, <mutation>)", domainID)
	shardID, err := m.randShard(ctx, domainID)
	if err != nil {
		return err
	}
	mData, err := proto.Marshal(update)
	if err != nil {
		return err
	}
	// TODO(gbelvin): Implement retry with backoff for retryable errors if
	// we get timestamp contention.
	return m.send(ctx, domainID, shardID, mData, time.Now())
}

// randShard returns a random, enabled shard for domainID.
func (m *Mutations) randShard(ctx context.Context, domainID string) (int64, error) {
	// TODO(gbelvin): Cache these results.
	var shardIDs []int64
	rows, err := m.db.QueryContext(ctx,
		`SELECT ShardID from Shards WHERE DomainID = ? AND Enabled = ?;`,
		domainID, true)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	for rows.Next() {
		var shardID int64
		if err := rows.Scan(&shardID); err != nil {
			return 0, err
		}
		shardIDs = append(shardIDs, shardID)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	if len(shardIDs) == 0 {
		return 0, status.Errorf(codes.NotFound, "No shard found for domain %v", domainID)
	}

	// Return a random shard.
	return shardIDs[rand.Intn(len(shardIDs))], nil
}

// ts must be greater than all other timestamps currently recorded for domainID.
func (m *Mutations) send(ctx context.Context, domainID string, shardID int64, mData []byte, ts time.Time) (ret error) {
	tx, err := m.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelSerializable})
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

	var maxTime int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(Time), 0) FROM Queue WHERE DomainID = ? AND ShardID = ?;`,
		domainID, shardID).Scan(&maxTime); err != nil {
		return status.Errorf(codes.Internal, "could not find max timestamp: %v", err)
	}
	tsTime := ts.UnixNano()
	if tsTime <= maxTime {
		return status.Errorf(codes.Aborted,
			"current timestamp: %v, want > max-timestamp of queued mutations: %v",
			tsTime, maxTime)
	}

	if _, err = tx.ExecContext(ctx,
		`INSERT INTO Queue (DomainID, ShardID, Time, Mutation) VALUES (?, ?, ?, ?);`,
		domainID, shardID, tsTime, mData); err != nil {
		return status.Errorf(codes.Internal, "failed inserting into queue: %v", err)
	}
	return tx.Commit()
}

// HighWatermarks returns the highest timestamp for each shard in the mutations table.
func (m *Mutations) HighWatermarks(ctx context.Context, domainID string) (map[int64]int64, error) {
	watermarks := make(map[int64]int64)
	rows, err := m.db.QueryContext(ctx,
		`SELECT ShardID, Max(Time) FROM Queue WHERE DomainID = ? GROUP BY ShardID;`,
		domainID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var shardID, watermark int64
		if err := rows.Scan(&shardID, &watermark); err != nil {
			return nil, err
		}
		watermarks[shardID] = watermark
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return watermarks, nil
}

// ReadQueue reads all mutations in shardID between (low, high].
func (m *Mutations) ReadQueue(ctx context.Context,
	domainID string, shardID, low, high int64) ([]*mutator.QueueMessage, error) {
	rows, err := m.db.QueryContext(ctx,
		`SELECT Time, Mutation FROM Queue
		WHERE DomainID = ? AND ShardID = ? AND Time > ? AND Time <= ?
		ORDER BY Time ASC;`,
		domainID, shardID, low, high)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return readQueueMessages(rows)
}

func readQueueMessages(rows *sql.Rows) ([]*mutator.QueueMessage, error) {
	results := make([]*mutator.QueueMessage, 0)
	for rows.Next() {
		var timestamp int64
		var mData []byte
		if err := rows.Scan(&timestamp, &mData); err != nil {
			return nil, err
		}
		entryUpdate := new(pb.EntryUpdate)
		if err := proto.Unmarshal(mData, entryUpdate); err != nil {
			return nil, err
		}
		results = append(results, &mutator.QueueMessage{
			ID:        timestamp,
			Mutation:  entryUpdate.Mutation,
			ExtraData: entryUpdate.Committed,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return results, nil
}

// DeleteMessages removes messages from the queue.
func (m *Mutations) DeleteMessages(ctx context.Context, domainID string, mutations []*mutator.QueueMessage) error {
	glog.V(4).Infof("mutationstorage: DeleteMessages(%v, <mutation>)", domainID)
	delStmt, err := m.db.Prepare(deleteQueueExpr)
	if err != nil {
		return err
	}
	defer delStmt.Close()
	var retErr error
	for _, mutation := range mutations {
		if _, err = delStmt.ExecContext(ctx, domainID, mutation.ID); err != nil {
			// If an error occurs, take note, but continue deleting
			// the other referenced mutations.
			retErr = err
		}
	}
	return retErr
}
