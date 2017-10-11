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
	"context"
	"database/sql"
	"fmt"

	"github.com/google/keytransparency/core/transaction"
)

// Factory represents a transaction factory for atomic database and queue ops.
type Factory struct {
	db *sql.DB
}

// NewFactory creates a new instance of the transaction factory.
func NewFactory(db *sql.DB) *Factory {
	return &Factory{
		db: db,
	}
}

// NewTxn creates a new transaction object.
func (f *Factory) NewTxn(ctx context.Context) (transaction.Txn, error) {
	// Create database transaction.
	dbTxn, err := f.db.Begin()
	if err != nil {
		return nil, err
	}

	// Create transaction object
	return &txn{
		ctx:   ctx,
		dbTxn: dbTxn,
	}, nil
}

// txn provides a cross-domain atomic transactions between SQL database and etcd.
type txn struct {
	ctx   context.Context
	dbTxn *sql.Tx
}

// Prepare prepares an SQL statement to be executed.
func (t *txn) Prepare(query string) (*sql.Stmt, error) {
	return t.dbTxn.Prepare(query)
}

// Commit commits the transaction. This implementation just wraps SQL database
// transaction commit function.
func (t *txn) Commit() error {
	if err := t.ctx.Err(); err != nil {
		if rbErr := t.Rollback(); rbErr != nil {
			err = fmt.Errorf("%v, Rollback(): %v", err, rbErr)
		}
		return err
	}

	// Commit the database transaction. On failure, we lose the mutation.
	if err := t.dbTxn.Commit(); err != nil {
		return fmt.Errorf("db.Commit(): %v", err)
	}
	return nil
}

// Rollback aborts the transaction. It rolls back the database transaction.
func (t *txn) Rollback() error {
	return t.dbTxn.Rollback()
}
