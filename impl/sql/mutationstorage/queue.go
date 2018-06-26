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
	"sync"
	"time"

	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// Send writes mutations to the leading edge (by sequence number) of the mutations table.
func (m *Mutations) Send(ctx context.Context, domainID string, update *pb.EntryUpdate) error {
	glog.Infof("queue.Send(%v, <mutation>)", domainID)
	mData, err := proto.Marshal(update)
	if err != nil {
		return err
	}
	writeStmt, err := m.db.Prepare(insertQueueExpr)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.ExecContext(ctx, domainID, time.Now().UnixNano(), mData)
	return err
}

// NewReceiver starts receiving messages sent to the queue. As batches become ready, recieveFunc will be called.
func (m *Mutations) NewReceiver(ctx context.Context, last time.Time, domainID string, recieveFunc mutator.ReceiveFunc, rOpts mutator.ReceiverOptions) mutator.Receiver {
	r := &Receiver{
		store:       m,
		domainID:    domainID,
		opts:        rOpts,
		ticker:      time.NewTicker(rOpts.Period),
		maxTicker:   time.NewTicker(rOpts.MaxPeriod),
		done:        make(chan interface{}),
		recieveFunc: recieveFunc,
	}

	go r.run(ctx, last)
	r.running.Add(1)
	return r
}

// Receiver receives messages from a queue.
type Receiver struct {
	store       *Mutations
	domainID    string
	recieveFunc mutator.ReceiveFunc
	opts        mutator.ReceiverOptions
	ticker      *time.Ticker
	maxTicker   *time.Ticker
	done        chan interface{}
	running     sync.WaitGroup
}

// Close stops the receiver and returns only when all callbacks are complete.
func (r *Receiver) Close() {
	close(r.done)
	r.running.Wait()
}

// FlushN verifies that a minimum of n items are available to send, and sends them.
func (r *Receiver) FlushN(ctx context.Context, n int) error {
	sent, err := r.sendMultiBatch(ctx, n, int(r.opts.MaxBatchSize))
	if err != nil {
		return err
	}
	if sent < n {
		// We could retry at this point, but because this queue is mysql based
		// and deterministic, we know that waiting won't be very useful.
		return fmt.Errorf("sendMultiBatch(): %v, want >= %v", sent, n)
	}
	return nil
}

func (r *Receiver) run(ctx context.Context, last time.Time) {
	defer r.running.Done()

	if got, want := time.Since(last), r.opts.MaxPeriod; got > want {
		glog.Warningf("MMD Blown: Time since last revision: %v, want < %v", got, want)
	}

	if time.Since(last) > (r.opts.MaxPeriod - r.opts.Period) {
		if _, err := r.sendMultiBatch(ctx, 0, int(r.opts.MaxBatchSize)); err != nil {
			glog.Errorf("firstTick: sendMultiBatch(): %v", err)
		}
	}

	for {
		select {
		case <-r.ticker.C:
			if _, err := r.sendMultiBatch(ctx, 1, int(r.opts.MaxBatchSize)); err != nil {
				glog.Errorf("minTick: sendMultiBatch(): %v", err)
			}
		case <-r.maxTicker.C:
			if _, err := r.sendMultiBatch(ctx, 0, int(r.opts.MaxBatchSize)); err != nil {
				glog.Errorf("maxTick: sendMultiBatch(): %v", err)
			}
		case <-ctx.Done():
			return
		case <-r.done:
			return
		}
	}
}

// sendMultiBatch will send multiple batches if the number of available messages > maxMsgs.
// This helps the queue catch up when there is high traffic, rather than waiting for the next
// mintick to occur.
func (r *Receiver) sendMultiBatch(ctx context.Context, minMsgs, maxMsgs int) (int, error) {
	var total int
	var err error
	for sent := maxMsgs; sent >= maxMsgs; {
		sent, err = r.sendBatch(ctx, minMsgs, maxMsgs)
		total += sent
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// sendBatch sends up to batchSize items to the receiver. Returns the number of sent items.
// If the number of available items is < minBatch, 0 items are sent.
// If the number of available items is > maxBatch only maxBatch items are sent.
func (r *Receiver) sendBatch(ctx context.Context, minBatch, maxBatch int) (int, error) {
	ms, err := r.store.readQueue(ctx, r.domainID, int32(maxBatch))
	if err != nil {
		return 0, fmt.Errorf("readQueue(): %v", err)
	}
	if len(ms) < minBatch {
		return 0, nil
	}

	if err := r.recieveFunc(ms); err != nil {
		return 0, fmt.Errorf("queue.SendBatch(): %v", err)
	}
	// TODO(gbelvin): Do we need finer grained errors?
	// We could put an ack'ed field in a QueueMessage object.
	// But I don't think we need that level of granularity -- yet?

	// Delete old messages.
	if err := r.store.deleteMessages(ctx, r.domainID, ms); err != nil {
		return 0, fmt.Errorf("deleteQueueMessages(%v, len(ms): %v): %v", r.domainID, len(ms), err)
	}

	return len(ms), nil
}

// readQueue reads all mutations that are still in the queue up to batchSize.
func (m *Mutations) readQueue(ctx context.Context, domainID string, batchSize int32) ([]*mutator.QueueMessage, error) {
	readStmt, err := m.db.Prepare(readQueueExpr)
	if err != nil {
		return nil, err
	}
	defer readStmt.Close()
	rows, err := readStmt.QueryContext(ctx, domainID, batchSize)
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

func (m *Mutations) deleteMessages(ctx context.Context, domainID string, mutations []*mutator.QueueMessage) error {
	glog.V(4).Infof("queue.Delete(%v, <mutation>)", domainID)
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
