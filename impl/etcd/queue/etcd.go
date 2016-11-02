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
	"time"

	"github.com/google/key-transparency/core/queue"
	ctxn "github.com/google/key-transparency/core/transaction"
	itxn "github.com/google/key-transparency/impl/transaction"

	v3 "github.com/coreos/etcd/clientv3"
	"github.com/coreos/etcd/etcdserver/api/v3rpc/rpctypes"
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
func New(ctx context.Context, client *v3.Client, mapID string, factory *itxn.Factory) *Queue {
	return &Queue{
		client:    client,
		ctx:       ctx,
		keyPrefix: mapID,
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
		txnresp, err := q.client.Txn(q.ctx).Then(req).Commit()
		if err == nil {
			return newKey, txnresp.Header.Revision, nil
		} else if err != rpctypes.ErrDuplicateKey {
			return "", -1, err
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
				log.Printf(err.Error())
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
	if err := processEntry(txn, cbs, dataKV); err != nil {
		return err
	}

	// Commit the transaction.
	if err := txn.Commit(); err != nil {
		return err
	}
	return nil
}

// processEntry processes a given queue item.
func processEntry(txn ctxn.Txn, cbs callbacks, dataKV kv) error {
	// Process the entry.
	if dataKV.AdvanceEpoch {
		return cbs.advanceFunc(txn)
	}
	return cbs.processFunc(txn, dataKV.Key, dataKV.Val)
}

// Close stops the receiver from receiving items from the queue.
func (r *receiver) Close() {
	r.cancel()
}
