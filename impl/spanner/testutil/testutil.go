// Copyright 2020 Google Inc. All Rights Reserved.
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

// Package testutil helps with tests against Spanner.
package testutil

import (
	"context"
	"flag"
	"fmt"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/spannertest"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	databasepb "google.golang.org/genproto/googleapis/spanner/admin/database/v1"
)

var testDBFlag = flag.String("test_db", "", "Fully-qualified database name to test against; empty means use an in-memory fake.")

var dbCount struct {
	sync.Mutex
	count int
}

func uniqueDBName() string {
	dbCount.Lock()
	database := fmt.Sprintf("fake-db%d", dbCount.count)
	dbCount.count++
	dbCount.Unlock()
	const instance = "fake-instance"
	const project = "fake-proj"
	return fmt.Sprintf("projects/%s/instances/%s/databases/%s", project, instance, database)
}

func CreateDatabase(ctx context.Context, t testing.TB, ddlStatements []string) (*spanner.Client, func()) {
	dbName, client, adminClient, cleanup := client(ctx, t)
	updateDDL(ctx, t, dbName, adminClient, ddlStatements...)
	return client, cleanup
}

func client(ctx context.Context, t testing.TB) (string, *spanner.Client, *database.DatabaseAdminClient, func()) {
	if dbName := *testDBFlag; dbName != "" {
		client, adminClient, cleanup := realClient(ctx, t, dbName)
		return dbName, client, adminClient, cleanup
	}
	dbName := uniqueDBName()
	client, adminClient, cleanup := inMemClient(ctx, t, dbName)
	return dbName, client, adminClient, cleanup
}

func inMemClient(ctx context.Context, t testing.TB, dbName string) (*spanner.Client, *database.DatabaseAdminClient, func()) {
	t.Helper()
	// Don't use SPANNER_EMULATOR_HOST because we need the raw connection for
	// the database admin client anyway.

	t.Logf("Using in-memory fake Spanner DB: %s", dbName)
	srv, err := spannertest.NewServer("localhost:0")
	if err != nil {
		t.Fatalf("Starting in-memory fake: %v", err)
	}
	srv.SetLogger(t.Logf)
	dialCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, srv.Addr, grpc.WithInsecure())
	if err != nil {
		srv.Close()
		t.Fatalf("Dialing in-memory fake: %v", err)
	}
	client, err := spanner.NewClient(ctx, dbName, option.WithGRPCConn(conn))
	if err != nil {
		srv.Close()
		t.Fatalf("Connecting to in-memory fake: %v", err)
	}
	adminClient, err := database.NewDatabaseAdminClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		srv.Close()
		t.Fatalf("Connecting to in-memory fake DB admin: %v", err)
	}
	return client, adminClient, func() {
		client.Close()
		adminClient.Close()
		conn.Close()
		srv.Close()
	}
}

func realClient(ctx context.Context, t testing.TB, dbName string) (*spanner.Client, *database.DatabaseAdminClient, func()) {
	t.Logf("Using real Spanner DB: %s", dbName)
	cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, err := spanner.NewClient(cctx, dbName)
	if err != nil {
		t.Fatalf("Connecting to %s: %v", dbName, err)
	}
	adminClient, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		client.Close()
		t.Fatalf("Connecting DB admin client: %v", err)
	}
	return client, adminClient, func() { client.Close(); adminClient.Close() }
}

func updateDDL(ctx context.Context, t testing.TB, dbName string, adminClient *database.DatabaseAdminClient, statements ...string) error {
	t.Helper()
	t.Logf("DDL update: %q", statements)
	op, err := adminClient.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Database:   dbName,
		Statements: statements,
	})
	if err != nil {
		t.Fatalf("Starting DDL update: %v", err)
	}
	return op.Wait(ctx)
}
