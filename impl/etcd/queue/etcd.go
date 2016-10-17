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
	"log"

	"github.com/google/key-transparency/core/queue"
	ctxn "github.com/google/key-transparency/core/transaction"
	itxn "github.com/google/key-transparency/impl/transaction"

	"golang.org/x/net/context"

	v3 "github.com/coreos/etcd/clientv3"
	recipe "github.com/coreos/etcd/contrib/recipes"
)

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
	return q.enqueue(buf.Bytes())
}

// Enqueue submits a key, value pair into the queue.
func (q *Queue) Enqueue(key, value []byte) error {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(kv{key, value, false}); err != nil {
		return err
	}
	return q.enqueue(buf.Bytes())
}

func (q *Queue) enqueue(val []byte) error {
	_, err := recipe.NewUniqueKV(q.client, q.keyPrefix, string(val), 0)
	return err
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
			var dataKV kv
			dec := gob.NewDecoder(bytes.NewBuffer(ev.Kv.Value))
			if err := dec.Decode(&dataKV); err != nil {
				log.Printf(err.Error())
				continue
			}

			// Create a cross-domain transaction.
			txn, err := q.factory.NewTxn(q.ctx, string(ev.Kv.Key), ev.Kv.ModRevision)
			if err != nil {
				log.Printf(err.Error())
				continue
			}

			// Process the received entry.
			if err := processEntry(txn, cbs, dataKV); err != nil {
				log.Printf(err.Error())
				continue
			}

			// Commit the transaction.
			if err := txn.Commit(); err != nil {
				log.Printf(err.Error())
			}
		}
	}
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
