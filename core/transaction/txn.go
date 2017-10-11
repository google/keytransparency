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
)

// Factory represents a transaction factory object.
type Factory interface {
	// NewTxn creates a new transaction object for database operations.
	NewTxn(ctx context.Context) (Txn, error)
}

// Txn represents a transaction interface that provides atomic SQL database and
// queue operations.
type Txn interface {
	// Prepare prepares an SQL statement to be executed.
	Prepare(query string) (*sql.Stmt, error)
	// Commit commits the transaction.
	Commit() error
	// Rollback aborts the transaction.
	Rollback() error
}
