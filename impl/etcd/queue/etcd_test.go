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
	"database/sql"
	"encoding/gob"
	"sync"
	"testing"
	"time"

	ctxn "github.com/google/keytransparency/core/transaction"
	itxn "github.com/google/keytransparency/impl/transaction"

	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
	"golang.org/x/net/context"
)

const mapID = 1

var clusterSize = 3

// newDB creates a new in-memory database for testing.
func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

// TestStartReceiving tests that the queue is receiving the correct enqueued
// items. The test does not depend on the order the items are received.
func TestStartReceiving(t *testing.T) {
	c := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	defer c.Terminate(t)

	cli := c.RandClient()
	factory := itxn.NewFactory(newDB(t), cli)
	q := New(context.Background(), cli, mapID, factory)

	// Prepare test data.
	litems := []struct {
		key   string
		value string
	}{
		{"1", "one"},
		{"2", "two"},
		{"3", "three"},
		{"4", "four"},
		{"5", "five"},
	}

	// Use map to allow removal of already received items. At the end
	// of the test case, this map should be empty.
	mitems := make(map[string]string)
	for _, v := range litems {
		mitems[v.key] = v.value
	}

	// StartReceiving setup.
	var done sync.WaitGroup
	done.Add(len(mitems))
	processFunc := func(ctx context.Context, txn ctxn.Txn, sequence uint64, key, value []byte) error {
		if v, ok := mitems[string(key)]; !ok {
			t.Errorf("Receive key %v was not enqueued", key)
		} else {
			if got, want := value, []byte(v); !bytes.Equal(got, want) {
				t.Errorf("Received the wrong value for key %v: %v, want %v", key, got, want)
			}
		}
		// Remove received item from items map.
		delete(mitems, string(key))
		done.Done()
		return nil
	}
	advanceFunc := func(ctx context.Context, txn ctxn.Txn) error { return nil }
	if _, err := q.StartReceiving(processFunc, advanceFunc); err != nil {
		t.Fatalf("failed to start queue receiver: %v", err)
	}

	// Enqueue all items.
	for _, v := range litems {
		if err := q.Enqueue([]byte(v.key), []byte(v.value)); err != nil {
			t.Errorf("Enqueue(%v, %v): %v", v.key, v.value, err)
		}
	}

	// Wait for the goroutine to stop.
	done.Wait()

	// Ensure items map is empty.
	if got, want := len(mitems), 0; got != want {
		t.Errorf("len(mitems)=%v, want %v", got, want)
	}
}

func TestProcessEntry(t *testing.T) {
	// Setup
	var pCounter, aCounter int
	cbs := callbacks{
		func(ctx context.Context, txn ctxn.Txn, sequence uint64, key, value []byte) error {
			pCounter++
			return nil
		},
		func(ctx context.Context, txn ctxn.Txn) error {
			aCounter++
			return nil
		},
	}

	for _, tc := range []struct {
		pCounter, aCounter int
		kvs                []kv
	}{
		{1, 0, []kv{
			{nil, nil, false},
		}},
		{0, 1, []kv{
			{nil, nil, true},
		}},
		{3, 2, []kv{
			{nil, nil, true},
			{nil, nil, false},
			{nil, nil, true},
			{nil, nil, false},
			{nil, nil, false},
		}},
	} {
		// Restart counters
		pCounter = 0
		aCounter = 0

		for _, kv := range tc.kvs {
			_ = processEntry(context.Background(), nil, cbs, kv)
		}

		if got, want := pCounter, tc.pCounter; got != want {
			t.Errorf("pCounter=%v, want %v", got, want)
		}

		if got, want := aCounter, tc.aCounter; got != want {
			t.Errorf("aCounter=%v, want %v", got, want)
		}
	}
}

func TestKVTimeout(t *testing.T) {
	defer func(oldTTL int64) {
		leaseTTL = oldTTL
	}(leaseTTL)
	// Make TTL 1 seconds.
	leaseTTL = 1

	c := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	defer c.Terminate(t)

	cli := c.RandClient()
	factory := itxn.NewFactory(newDB(t), cli)
	q := New(context.Background(), cli, mapID, factory)

	value := kv{[]byte("test_key"), []byte("test_value"), false}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(value); err != nil {
		t.Fatalf("gob encoding failed: %v", err)
	}

	cbs := callbacks{
		func(ctx context.Context, txn ctxn.Txn, sequence uint64, key, value []byte) error {
			return nil
		},
		func(ctx context.Context, txn ctxn.Txn) error {
			return nil
		},
	}

	for _, tc := range []struct {
		sleep   int
		success bool
	}{
		{0, true},
		{2, false},
	} {
		key, rev, err := q.enqueue(buf.Bytes())
		if err != nil {
			t.Errorf("enqueue failed: %v", err)
			continue
		}

		time.Sleep(time.Duration(tc.sleep) * time.Second)

		err = q.dequeue([]byte(key), buf.Bytes(), rev, cbs)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("dequeue(%v, _, _, _)=%v, want %v, error %v", key, got, want, err)
		}
	}
}
