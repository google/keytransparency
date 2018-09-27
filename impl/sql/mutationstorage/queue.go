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
	"strings"
	"time"

	"github.com/google/keytransparency/core/mutator"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// Send writes mutations to the leading edge (by sequence number) of the mutations table.
func (m *Mutations) Send(ctx context.Context, domainID string, update *pb.EntryUpdate) error {
	return m.send(ctx, domainID, update, time.Now())
}

func (m *Mutations) send(ctx context.Context, domainID string, update *pb.EntryUpdate, ts time.Time) error {
	glog.Infof("mutationstorage: Send(%v, <mutation>)", domainID)
	mData, err := proto.Marshal(update)
	if err != nil {
		return err
	}
	writeStmt, err := m.db.Prepare(insertQueueExpr)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.ExecContext(ctx, domainID, ts.UnixNano(), mData)
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint") {
		return status.Errorf(codes.Aborted, "Clashing timestamp: %v. Try again", err)
	}
	return err
}

// HighWatermark returns the highest timestamp in the mutations table.
func (m *Mutations) HighWatermark(ctx context.Context, domainID string) (int64, error) {
	readStmt, err := m.db.Prepare(readQueueWatermarkExpr)
	if err != nil {
		return 0, err
	}
	defer readStmt.Close()
	row := readStmt.QueryRowContext(ctx, domainID)
	var watermark int64
	if err := row.Scan(&watermark); err == sql.ErrNoRows {
		return 0, nil
	} else if err != nil {
		return 0, err
	}
	return watermark, err
}

// ReadQueue reads all mutations that are still in the queue up to batchSize.
func (m *Mutations) ReadQueue(ctx context.Context, domainID string, low, high int64) ([]*mutator.QueueMessage, error) {
	readStmt, err := m.db.Prepare(readQueueExpr)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()
	rows, err := readStmt.QueryContext(ctx, domainID, low, high)
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
