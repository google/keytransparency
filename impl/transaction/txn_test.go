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
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/context"
)

type env struct {
	db      *sql.DB
	factory *Factory
}

func newEnv(t *testing.T) *env {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	factory := NewFactory(db)
	return &env{db, factory}
}

func (e *env) Close(t *testing.T) {
	e.db.Close()
}

func TestNewTxn(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	if _, err := env.factory.NewTxn(context.Background()); err != nil {
		t.Errorf("NewTxn failed: %v", err)
	}
}

func TestExpiredContext(t *testing.T) {
	env := newEnv(t)
	defer env.Close(t)

	ctx, cancel := context.WithCancel(context.Background())
	txn, err := env.factory.NewTxn(ctx)
	if err != nil {
		t.Fatalf("NewTxn failed: %v", err)
	}

	cancel()
	if err := txn.Commit(); err == nil {
		t.Errorf("txn.Commit() unexpectedly succeeded")
	}
}

func TestCommit(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	defer env.Close(t)

	txn, err := env.factory.NewTxn(ctx)
	if err != nil {
		t.Fatalf("NewTxn failed: %v", err)
	}

	// Commit the transaction. It should succeed.
	if err := txn.Commit(); err != nil {
		t.Errorf("txn.Commit() failed: %v", err)
	}
}

func TestFailedDBTxnCommit(t *testing.T) {
	ctx := context.Background()
	env := newEnv(t)
	defer env.Close(t)

	txn, err := env.factory.NewTxn(ctx)
	if err != nil {
		t.Fatalf("NewTxn failed: %v", err)
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
	ctx := context.Background()
	env := newEnv(t)
	defer env.Close(t)

	for _, tc := range []struct {
		commit  bool
		success bool
	}{
		{false, true},
		{true, false},
	} {
		txn, err := env.factory.NewTxn(ctx)
		if err != nil {
			t.Fatalf("NewTxn failed: %v", err)
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
