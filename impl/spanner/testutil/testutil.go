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
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/spannertest"
	"google.golang.org/api/option"
	"google.golang.org/grpc"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	databasepb "google.golang.org/genproto/googleapis/spanner/admin/database/v1"
)

var dbCount uint32

func uniqueDBName() string {
	const project = "fake-proj"
	const instance = "fake-instance"
	database := fmt.Sprintf("fake-db-%d", atomic.AddUint32(&dbCount, 1))
	return fmt.Sprintf("projects/%s/instances/%s/databases/%s", project, instance, database)
}

// CreateDatabse returns a connection to a 1 time use database with the given DDL schema.
func CreateDatabase(ctx context.Context, t testing.TB, ddlStatements []string) *spanner.Client {
	dbName := uniqueDBName()
	client, adminClient := inMemClient(ctx, t, dbName)
	updateDDL(ctx, t, dbName, adminClient, ddlStatements...)
	return client
}

func inMemClient(ctx context.Context, t testing.TB, dbName string) (*spanner.Client, *database.DatabaseAdminClient) {
	t.Helper()
	// Don't use SPANNER_EMULATOR_HOST because we need the raw connection for
	// the database admin client anyway.

	t.Logf("Using in-memory fake Spanner DB: %s", dbName)
	srv, err := spannertest.NewServer("localhost:0")
	if err != nil {
		t.Fatalf("Starting in-memory fake: %v", err)
	}
	t.Cleanup(srv.Close)
	srv.SetLogger(t.Logf)
	dialCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
	defer cancel()
	conn, err := grpc.DialContext(dialCtx, srv.Addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dialing in-memory fake: %v", err)
	}
	client, err := spanner.NewClient(ctx, dbName, option.WithGRPCConn(conn))
	if err != nil {
		conn.Close()
		t.Fatalf("Connecting to in-memory fake: %v", err)
	}
	t.Cleanup(client.Close)
	adminClient, err := database.NewDatabaseAdminClient(ctx, option.WithGRPCConn(conn))
	if err != nil {
		t.Fatalf("Connecting to in-memory fake DB admin: %v", err)
	}
	return client, adminClient
}

func updateDDL(ctx context.Context, t testing.TB, dbName string, adminClient *database.DatabaseAdminClient, statements ...string) {
	t.Helper()
	t.Logf("DDL update: %s", statements)
	op, err := adminClient.UpdateDatabaseDdl(ctx, &databasepb.UpdateDatabaseDdlRequest{
		Database:   dbName,
		Statements: statements,
	})
	if err != nil {
		t.Fatalf("Starting DDL update: %v", err)
	}
	if err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}
