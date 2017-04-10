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
	"errors"
	"fmt"

	"github.com/google/keytransparency/core/transaction"

	v3 "github.com/coreos/etcd/clientv3"
	"golang.org/x/net/context"
)

var (
	errInvalidIDs = errors.New("invalid identifiers (ids)")
)

// Factory represents a transaction factory for atomic database and queue ops.
type Factory struct {
	db     *sql.DB
	client *v3.Client
}

// NewFactory creates a new instance of the transaction factory.
func NewFactory(db *sql.DB, client *v3.Client) *Factory {
	return &Factory{
		db:     db,
		client: client,
	}
}

// NewTxn creates a new transaction object.
func (f *Factory) NewTxn(ctx context.Context, key string, rev int64) (transaction.Txn, error) {
	// Create database transaction.
	dbTxn, err := f.db.Begin()
	if err != nil {
		return nil, err
	}

	// Create queue transaction.
	queueTxn := f.client.Txn(ctx)

	// Create transaction object
	return &txn{ctx, dbTxn, queueTxn, key, rev}, nil
}

// NewDBTxn creates a new transaction object to only support database operations.
func (f *Factory) NewDBTxn(ctx context.Context) (transaction.Txn, error) {
	// Create database transaction.
	dbTxn, err := f.db.Begin()
	if err != nil {
		return nil, err
	}

	// Create transaction object
	return &txn{ctx, dbTxn, nil, "", -1}, nil
}

// txn provides a cross-domain atomic transactions between SQL database and etcd.
type txn struct {
	ctx      context.Context
	dbTxn    *sql.Tx
	queueTxn v3.Txn
	// Key and rev are needed by the etcd queue for deletion.
	key string
	rev int64
}

// Prepare prepares an SQL statement to be executed.
func (t *txn) Prepare(query string) (*sql.Stmt, error) {
	return t.dbTxn.Prepare(query)
}

// Commit commits the transaction. First, it deletes a queue item with matching
// key and rev. If the delete failed due to any reason including not found key,
// the database transaction is rolled back. Then, Commit attempts to commit the
// DB transaction. An error is returned on failure and the mutation being
// processed is lost. If this transaction object is created using NewDBTxn, only
// the database transaction will be committed.
func (t *txn) Commit() error {
	if err := t.ctx.Err(); err != nil {
		if rbErr := t.Rollback(); rbErr != nil {
			err = fmt.Errorf("%v, Rollback(): %v", err, rbErr)
		}
		return err
	}

	// Delete the queue element only if queueTxn is set.
	if t.queueTxn != nil {
		// cmp ensures that the key has the correct revision.
		cmp := v3.Compare(v3.ModRevision(t.key), "=", t.rev)
		req := v3.OpDelete(t.key)
		resp, cErr := t.queueTxn.If(cmp).Then(req).Commit()
		// If the key does not exist, queueTxn Commit returns a nil error
		// but sets resp.Succeeded to false. Key does not exist can
		// happen because another receiver might have already processed
		// the item and deleted it from the queue.
		var err error
		switch {
		case cErr != nil:
			err = fmt.Errorf("queue commit failed: %v", cErr)
		case !resp.Succeeded:
			err = fmt.Errorf("queue commit failed: key not found")
		}
		// If commit failed or the item was not found, rollback DB
		// transaction.
		if err != nil {
			if rbErr := t.Rollback(); rbErr != nil {
				err = fmt.Errorf("%v, Rollback(): %v", err, rbErr)
			}
			return err
		}
	}

	// Commit the database transaction. On failure, we lose the mutation.
	if err := t.dbTxn.Commit(); err != nil {
		return fmt.Errorf("db.Commit(): %v", err)
	}
	return nil
}

// Rollback aborts the transaction. It only rolls back the database transaction.
func (t *txn) Rollback() error {
	return t.dbTxn.Rollback()
}
