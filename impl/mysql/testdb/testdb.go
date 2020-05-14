// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package testdb supports opening ephemeral databases for testing.
package testdb

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"testing"
	"time"

	ktsql "github.com/google/keytransparency/impl/mysql"
)

var dataSourceURI = flag.String("kt_test_mysql_uri", "root@tcp(127.0.0.1)/", "The MySQL URI to use when running tests")

// NewForTest creates a temporary database.
// Returns a function for deleting the database.
func NewForTest(ctx context.Context, t testing.TB) *sql.DB {
	t.Helper()
	db, err := ktsql.Open(*dataSourceURI)
	if err != nil {
		t.Fatal(err)
	}

	dbName := fmt.Sprintf("test_%v", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Open test database
	db.Close()
	db, err = ktsql.Open(*dataSourceURI + dbName)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		ctx := context.Background()
		defer db.Close()
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE `%s`", dbName)); err != nil {
			log.Printf("Failed to drop test database %q: %v", dbName, err)
		}
	})
	return db
}
