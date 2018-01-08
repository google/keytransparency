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
	"sync"
	"time"

	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

// Send writes mutations to the leading edge (by sequence number) of the mutations table.
func (m *Mutations) Send(ctx context.Context, mapID int64, update *pb.EntryUpdate) error {
	glog.Infof("queue.Send(%v, <mutation>)", mapID)
	index := update.GetMutation().GetIndex()
	mData, err := proto.Marshal(update)
	if err != nil {
		return err
	}
	writeStmt, err := m.db.Prepare(insertExpr)
	if err != nil {
		return err
	}
	defer writeStmt.Close()
	_, err = writeStmt.ExecContext(ctx, mapID, index, mData)
	return err
}

// NewReceiver starts receiving messages sent to the queue. As batches become ready, recieveFunc will be called.
func (m *Mutations) NewReceiver(ctx context.Context, last time.Time, mapID, start int64, recieveFunc mutator.ReceiveFunc, rOpts mutator.ReceiverOptions) mutator.Receiver {
	r := &Receiver{
		store:       m,
		start:       start,
		mapID:       mapID,
		opts:        rOpts,
		more:        make(chan time.Time, 1),
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
	store       mutator.MutationStorage
	start       int64
	mapID       int64
	recieveFunc mutator.ReceiveFunc
	opts        mutator.ReceiverOptions
	more        chan time.Time
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

// Flush sends any waiting queue items.
func (r *Receiver) Flush(ctx context.Context) {
	r.sendBatch(ctx, true)
}

func (r *Receiver) run(ctx context.Context, last time.Time) {
	defer r.running.Done()

	if got, want := time.Since(last), r.opts.MaxPeriod; got > want {
		glog.Warningf("MMD Blown: Time since last revision: %v, want < %v", got, want)
	}

	if time.Since(last) > (r.opts.MaxPeriod - r.opts.Period) {
		r.sendBatch(ctx, true) // We will be overdue for an epoch soon.
	}

	for {
		var count int32
		select {
		case <-r.more:
			count = r.sendBatch(ctx, false)
		case <-r.ticker.C:
			count = r.sendBatch(ctx, false)
		case <-r.maxTicker.C:
			count = r.sendBatch(ctx, true)
		case <-ctx.Done():
			return
		case <-r.done:
			return
		}
		if count >= r.opts.MaxBatchSize {
			// Continue sending until we drop below batch size.
			r.more <- time.Now()
		}
	}
}

// sendBatch sends up to batchSize items to the receiver. Returns the number of sent items.
func (r *Receiver) sendBatch(ctx context.Context, sendEmpty bool) int32 {
	max, ms, err := r.store.ReadBatch(ctx, r.mapID, r.start, r.opts.MaxBatchSize)
	if err != nil {
		glog.Errorf("ReadBatch(%v): %v", r.start, err)
		return 0
	}
	if len(ms) == 0 && !sendEmpty {
		return 0
	}

	if err := r.recieveFunc(ms); err != nil {
		glog.Infof("queue.SendBatch failed: %v", err)
		return 0
	}
	// TODO(gbelvin): Do we need finer grained errors?
	// We could put an ack'ed field in a QueueMessage object.
	// But I don't think we need that level of granularity -- yet?

	// Update our own high water mark.
	r.start = max
	return int32(len(ms))
}
