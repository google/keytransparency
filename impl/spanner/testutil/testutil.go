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
	"os"
	"path"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"cloud.google.com/go/spanner/spannertest"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	database "cloud.google.com/go/spanner/admin/database/apiv1"
	instance "cloud.google.com/go/spanner/admin/instance/apiv1"
	databasepb "google.golang.org/genproto/googleapis/spanner/admin/database/v1"
	instancepb "google.golang.org/genproto/googleapis/spanner/admin/instance/v1"
)

var (
	inmemFlag    = flag.Bool("fake_db", true, "Use an in-memory fake.")
	projectFlag  = flag.String("db_project", "fake-proj", "GCP project to test against")
	instanceFlag = flag.String("db_instance", "fake-instance", "Spanner instance to test against")
)

// Unique per test binary invocation
var timestamp = time.Now().UTC().Format("jan-02-15-04-05")
var testBinary = strings.ToLower(strings.Replace(path.Base(os.Args[0]), ".test", "", 1))
var invocationID = fmt.Sprintf("%s-%s", timestamp, testBinary)
var dbCount uint32 // Unique per test invocation

func uniqueDBName(project, instance string) string {
	database := fmt.Sprintf("%s-%d", invocationID, atomic.AddUint32(&dbCount, 1))
	return fmt.Sprintf("projects/%s/instances/%s/databases/%s", project, instance, database)
}

// CreateDatabse returns a connection to a 1 time use database with the given DDL schema.
func CreateDatabase(ctx context.Context, t testing.TB, ddlStatements []string) *spanner.Client {
	var client *spanner.Client
	var adminClient *database.DatabaseAdminClient

	project := *projectFlag
	instance := *instanceFlag
	emulatorAddr := os.Getenv("SPANNER_EMULATOR_HOST")
	var dbName string
	switch {
	case *inmemFlag: // In-Mem
		dbName = uniqueDBName(project, instance)
		client, adminClient = inMemClient(ctx, t, dbName)
	case emulatorAddr != "": // Emulator
		dbName = uniqueDBName(project, instance)
		t.Logf("Using Spanner Emulator DB: %q", dbName)
		client, adminClient = realClient(ctx, t, dbName)
		createInstance(ctx, t, dbName)
		createDatabase(ctx, t, dbName, adminClient)
	default: // Real
		dbName = uniqueDBName(project, instance)
		t.Logf("Using real Spanner DB: %q", dbName)
		client, adminClient = realClient(ctx, t, dbName)
		createDatabase(ctx, t, dbName, adminClient)
	}
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

func realClient(ctx context.Context, t testing.TB, dbName string) (*spanner.Client, *database.DatabaseAdminClient) {
	t.Helper()
	client, err := spanner.NewClient(ctx, dbName)
	if err != nil {
		t.Fatalf("Connecting to %s: %v", dbName, err)
	}
	t.Cleanup(client.Close)
	adminClient, err := database.NewDatabaseAdminClient(ctx)
	if err != nil {
		t.Fatalf("Connecting DB admin client: %v", err)
	}
	t.Cleanup(func() {
		if err := adminClient.Close(); err != nil {
			t.Error(err)
		}
	})
	return client, adminClient
}

var dbRE = regexp.MustCompile(`projects/([a-z][-a-z0-9]*[a-z0-9])/instances/([a-z][-a-z0-9]*[a-z0-9])/databases/([a-z][-_a-z0-9]*[a-z0-9])`)

func parseDBName(t testing.TB, dbName string) (projectID, instanceID, databaseID string) {
	args := dbRE.FindStringSubmatch(dbName)
	if got := len(args); got != 4 {
		t.Fatalf("dbName %q did not match regex", dbName)
	}
	projectID = args[1]
	instanceID = args[2]
	databaseID = args[3]
	return
}

func createInstance(ctx context.Context, t testing.TB, dbName string) {
	projectID, instanceID, _ := parseDBName(t, dbName)

	client, err := instance.NewInstanceAdminClient(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	op, err := client.CreateInstance(ctx, &instancepb.CreateInstanceRequest{
		Parent:     fmt.Sprintf("projects/%s", projectID),
		InstanceId: instanceID,
	})
	if status.Code(err) == codes.AlreadyExists {
		return
	}
	if err != nil {
		t.Fatalf("CreateInstance: %v", err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}
}

func createDatabase(ctx context.Context, t testing.TB, dbName string, client *database.DatabaseAdminClient) {
	projectID, instanceID, databaseID := parseDBName(t, dbName)

	op, err := client.CreateDatabase(ctx, &databasepb.CreateDatabaseRequest{
		Parent:          fmt.Sprintf("projects/%s/instances/%s", projectID, instanceID),
		CreateStatement: fmt.Sprintf("CREATE DATABASE `%s`", databaseID),
	})
	if err != nil {
		t.Fatalf("CreateDatabase: %v", err)
	}
	if _, err := op.Wait(ctx); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() {
		if err := client.DropDatabase(ctx, &databasepb.DropDatabaseRequest{
			Database: fmt.Sprintf("projects/%s/instances/%s/databases/%s", projectID, instanceID, databaseID),
		}); err != nil {
			t.Errorf("DropDatabase(): %v", err)
		}
	})
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
