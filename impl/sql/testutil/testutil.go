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

// Package testutil contains test supporting functionality for 'impl/sql/...'.
package testutil

import (
	"context"
	"database/sql"

	"github.com/google/key-transparency/core/transaction"
)

// FakeFactory is a fake transaction factory
type FakeFactory struct {
	db *sql.DB
}

// NewFakeFactory creates a new FakeFactory instance.
func NewFakeFactory(db *sql.DB) *FakeFactory {
	return &FakeFactory{db}
}

// NewDBTxn creates a new database transaction.
func (f *FakeFactory) NewDBTxn(ctx context.Context) (transaction.Txn, error) {
	dbTxn, err := f.db.Begin()
	if err != nil {
		return nil, err
	}

	return &txn{dbTxn}, nil
}

type txn struct {
	dbTxn *sql.Tx
}

// Prepare prepares an SQL statement to be executed.
func (t *txn) Prepare(query string) (*sql.Stmt, error) {
	return t.dbTxn.Prepare(query)
}

// Commit commits the transaction.
func (t *txn) Commit() error {
	return t.dbTxn.Commit()
}

// Rollback aborts the transaction.
func (t *txn) Rollback() error {
	return t.dbTxn.Rollback()
}
