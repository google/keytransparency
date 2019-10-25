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

package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/go-sql-driver/mysql" // mysql driver
)

func NewForTest(ctx context.Context, t testing.TB) (*sql.DB, func(context.Context)) {
	config := mysql.NewConfig()
	config.User = "root"
	config.Net = "tcp"
	config.Addr = "127.0.0.1"

	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}

	dbName := fmt.Sprintf("test_%v", time.Now().UnixNano())
	if _, err := db.ExecContext(ctx, fmt.Sprintf("CREATE DATABASE `%s`", dbName)); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Open test database
	db.Close()
	config.DBName = dbName
	db, err = sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}

	done := func(ctx context.Context) {
		defer db.Close()
		if _, err := db.ExecContext(ctx, fmt.Sprintf("DROP DATABASE `%s`", dbName)); err != nil {
			log.Printf("Failed to drop test database %q: %v", dbName, err)
		}
	}
	return db, done
}
