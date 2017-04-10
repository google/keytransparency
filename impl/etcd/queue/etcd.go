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

package queue

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/google/keytransparency/core/queue"
	ctxn "github.com/google/keytransparency/core/transaction"
	itxn "github.com/google/keytransparency/impl/transaction"

	v3 "github.com/coreos/etcd/clientv3"
	"golang.org/x/net/context"
)

// leaseTTL is in seconds.
var leaseTTL = int64(30)

// Queue is a single-reader, multi-writer distributed queue.
type Queue struct {
	client    *v3.Client
	ctx       context.Context
	keyPrefix string
	factory   *itxn.Factory
}

type receiver struct {
	wc     v3.WatchChan
	cancel context.CancelFunc
}

type callbacks struct {
	processFunc queue.ProcessKeyValueFunc
	advanceFunc queue.AdvanceEpochFunc
}

type kv struct {
	Key          []byte
	Val          []byte
	AdvanceEpoch bool
}

// New creates a new consistent, distributed queue.
func New(ctx context.Context, client *v3.Client, mapID int64, factory *itxn.Factory) *Queue {
	return &Queue{
		client:    client,
		ctx:       ctx,
		keyPrefix: strconv.FormatInt(mapID, 10),
		factory:   factory,
	}
}

// AdvanceEpoch submits an advance epoch request into the queue.
func (q *Queue) AdvanceEpoch() error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(kv{nil, nil, true}); err != nil {
		return err
	}
	_, _, err := q.enqueue(buf.Bytes())
	return err
}

// Enqueue submits a key, value pair into the queue.
func (q *Queue) Enqueue(key, value []byte) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(kv{key, value, false}); err != nil {
		return err
	}
	_, _, err := q.enqueue(buf.Bytes())
	return err
}

func (q *Queue) enqueue(val []byte) (string, int64, error) {
	// Grant a lease with a TTL.
	resp, err := q.client.Grant(q.ctx, leaseTTL)
	if err != nil {
		return "", -1, err
	}
	for {
		newKey := fmt.Sprintf("%s/%v", q.keyPrefix, time.Now().UnixNano())
		req := v3.OpPut(newKey, string(val), v3.WithLease(resp.ID))
		cond := v3.Compare(v3.Version(newKey), "=", 0)
		txnresp, err := q.client.Txn(q.ctx).If(cond).Then(req).Commit()
		if err != nil {
			return "", -1, err
		}
		if txnresp.Succeeded {
			return newKey, txnresp.Header.Revision, nil
		}
	}
}

// StartReceiving starts receiving queue enqueued items. This function should be
// called as a Go routine.
func (q *Queue) StartReceiving(processFunc queue.ProcessKeyValueFunc, advanceFunc queue.AdvanceEpochFunc) (queue.Receiver, error) {
	// Ensure that callbacks are registered.
	if processFunc == nil || advanceFunc == nil {
		return nil, errors.New("nil function pointer")
	}

	cancelableCtx, cancel := context.WithCancel(q.ctx)
	wc := q.client.Watch(cancelableCtx, q.keyPrefix, v3.WithPrefix(), v3.WithFilterDelete())
	go q.loop(cancelableCtx, wc, callbacks{processFunc, advanceFunc})

	return &receiver{wc, cancel}, nil
}

func (q *Queue) loop(ctx context.Context, wc v3.WatchChan, cbs callbacks) {
	for resp := range wc {
		for _, ev := range resp.Events {
			if err := q.dequeue(ev.Kv.Key, ev.Kv.Value, ev.Kv.ModRevision, cbs); err != nil {
				log.Printf("Error: dequeue(): %v", err)
			}
		}
	}
}

func (q *Queue) dequeue(key, value []byte, rev int64, cbs callbacks) error {
	var dataKV kv
	dec := gob.NewDecoder(bytes.NewBuffer(value))
	if err := dec.Decode(&dataKV); err != nil {
		return err
	}

	// Create a cross-domain transaction.
	txn, err := q.factory.NewTxn(q.ctx, string(key), rev)
	if err != nil {
		return err
	}

	// Process the received entry.
	if err := processEntry(q.ctx, txn, cbs, dataKV); err != nil {
		if rErr := txn.Rollback(); rErr != nil {
			return fmt.Errorf("%v, Rollback: %v", err, rErr)
		}
		return err
	}

	// Commit the transaction.
	if err := txn.Commit(); err != nil {
		return fmt.Errorf("txn.Commit(advanceEpoch=%v): %v", dataKV.AdvanceEpoch, err)
	}
	return nil
}

// processEntry processes a given queue item.
func processEntry(ctx context.Context, txn ctxn.Txn, cbs callbacks, dataKV kv) error {
	// Process the entry.
	if dataKV.AdvanceEpoch {
		if err := cbs.advanceFunc(ctx, txn); err != nil {
			return fmt.Errorf("advanceFunc(): %v", err)
		}
	} else {
		if err := cbs.processFunc(ctx, txn, dataKV.Key, dataKV.Val); err != nil {
			return fmt.Errorf("processFunc(): %v", err)
		}
	}
	return nil
}

// Close stops the receiver from receiving items from the queue.
func (r *receiver) Close() {
	r.cancel()
}
