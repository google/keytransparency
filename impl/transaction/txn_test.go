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

package transaction

import (
	"database/sql"
	"fmt"
	"testing"

	"github.com/google/key-transparency/core/transaction"

	v3 "github.com/coreos/etcd/clientv3"
	recipe "github.com/coreos/etcd/contrib/recipes"
	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/context"
)

var (
	testKey     = "testkey"
	testValue   = "testvalue"
	testRev     = int64(1)
	testPrefix  = "testprefix"
	clusterSize = 3
)

type env struct {
	db      *sql.DB
	cluster *integration.ClusterV3
	cli     *v3.Client
	factory *Factory
}

func newEnv(t *testing.T) *env {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	c := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	cli := c.Client(0)
	factory := NewFactory(db, cli)

	return &env{db, c, cli, factory}
}

// append prepares the test by adding a new queue item and creating a txn.
func (e *env) append(ctx context.Context) (transaction.Txn, *recipe.RemoteKV, error) {
	// Add an item to the queue
	rkv, err := recipe.NewUniqueKV(e.cli, testPrefix, testValue, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("recipe.NewUniqueKV failed: %v", err)
	}

	// Create a transaction.
	txn, err := e.factory.NewTxn(context.Background(), rkv.Key(), rkv.Revision())
	if err != nil {
		return nil, nil, fmt.Errorf("NewTxn failed: %v", err)
	}

	return txn, rkv, nil
}

func (e *env) Close(t *testing.T) {
	e.db.Close()
	e.cluster.Terminate(t)
}

func TestNewTxn(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	if _, err := env.factory.NewTxn(context.Background(), testKey, testRev); err != nil {
		t.Errorf("NewTxn failed: %v", err)
	}
}

func TestExpiredContext(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	ctx, cancel := context.WithCancel(context.Background())
	txn, err := env.factory.NewTxn(ctx, testKey, testRev)
	if err != nil {
		t.Fatalf("NewTxn failed: %v", err)
	}

	cancel()
	if err := txn.Commit(); err == nil {
		t.Errorf("txn.Commit() unexpectedly succeeded")
	}
}

func TestCommit(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	// Add a new queue item and create a transaction.
	txn, _, err := env.append(context.Background())
	if err != nil {
		t.Fatalf("test preparation failed: %v", err)
	}

	// Commit the transaction. It should succeed.
	if err := txn.Commit(); err != nil {
		t.Errorf("txn.Commit() failed: %v", err)
	}
}

func TestDeletedQueueItem(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	// Add a new queue item and create a transaction.
	txn, rkv, err := env.append(context.Background())
	if err != nil {
		t.Fatalf("test preparation failed: %v", err)
	}

	// Delete the added item.
	if err := rkv.Delete(); err != nil {
		t.Fatalf("rkv.Delete() failed: %v", err)
	}

	// Commit the transaction. It should fail.
	if err := txn.Commit(); err == nil {
		t.Errorf("txn.Commit() unexpectedly succeeded")
	}
}

func TestFailedDBTxnCommit(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	// Add a new queue item and create a transaction.
	txn, _, err := env.append(context.Background())
	if err != nil {
		t.Fatalf("test preparation failed: %v", err)
	}

	// Rollback the database transaction
	if err := txn.Rollback(); err != nil {
		t.Fatalf("txn.Rollback() failed: %v", err)
	}

	// Commit the transaction. It should fail.
	if err := txn.Commit(); err == nil {
		t.Errorf("txn.Commit() unexpectedly succeeded")
	}
}

func TestRollback(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	for _, tc := range []struct {
		commit  bool
		success bool
	}{
		{false, true},
		{true, false},
	} {
		// Add a new queue item and create a transaction.
		txn, _, err := env.append(context.Background())
		if err != nil {
			t.Fatalf("test preparation failed: %v", err)
		}

		if tc.commit {
			if err := txn.Commit(); err != nil {
				t.Errorf("txn.Commit() failed: %v", err)
				continue
			}
		}

		if got, want := txn.Rollback() == nil, tc.success; got != want {
			t.Errorf("commit=%v and txn.Rollback()=%v, want %v", tc.commit, got, want)
		}
	}
}
