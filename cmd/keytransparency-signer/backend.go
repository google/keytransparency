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

package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/keytransparency/core/admin"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/mapserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/signer"
	ctxn "github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/impl/config"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/sql/sequenced"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/util"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

var (
	serverDBPath  = flag.String("db", "db", "Database connection string")
	domain        = flag.String("domain", "example.com", "Distinguished name for this key server")
	epochDuration = flag.Duration("period", time.Second*60, "Time between epoch creation")

	// Info to connect to sparse merkle tree database.
	mapID  = flag.Int64("map-id", 0, "ID for backend map")
	mapURL = flag.String("map-url", "", "URL of Trilian Map Server")

	// Info to replicate the Trillian Map Server locally.
	signingKey = flag.String("key", "", "Path to private key PEM for STH signing")

	// Info to send Signed Map Heads to a Trillian Log.
	logID     = flag.Int64("log-id", 0, "Trillian Log ID")
	logURL    = flag.String("log-url", "", "URL of Trillian Log Server for Signed Map Heads")
	logPubKey = flag.String("log-key", "", "File path to public key of the Trillian Log")
)

func openDB() *sql.DB {
	db, err := sql.Open(engine.DriverName, *serverDBPath)
	if err != nil {
		log.Fatalf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db.Ping(): %v", err)
	}
	return db
}

func newMapServer(ctx context.Context, sqldb *sql.DB, factory ctxn.Factory) (trillian.TrillianMapClient, error) {
	tree, err := sqlhist.New(ctx, *mapID, factory)
	if err != nil {
		return nil, fmt.Errorf("sqlhist.New(): %v", err)
	}

	sths, err := sequenced.New(sqldb, *mapID)
	if err != nil {
		return nil, err
	}

	signer, err := keys.NewFromPrivatePEM(*signingKey, "")
	if err != nil {
		return nil, err
	}

	return mapserver.New(*mapID, tree, factory, sths, signer,
		util.SystemTimeSource{}), nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb)

	// Connect to map server.
	var tmap trillian.TrillianMapClient
	if *mapURL != "" {
		mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
		if err != nil {
			log.Fatalf("grpc.Dial(%v): %v", *mapURL, err)
		}
		tmap = trillian.NewTrillianMapClient(mconn)
	} else {
		var err error
		tmap, err = newMapServer(context.Background(), sqldb, factory)
		if err != nil {
			log.Fatalf("newMapServer: %v", err)
		}
	}

	// Connection to append only log
	tlog, err := config.LogClient(*logID, *logURL, *logPubKey)
	if err != nil {
		log.Fatalf("LogClient(%v, %v, %v): %v", *logID, *logURL, *logPubKey, err)
	}

	// Create signer helper objects.
	static := admin.NewStatic()
	if err := static.AddLog(*logID, tlog); err != nil {
		log.Fatalf("static.AddLog(%v): %v", *mapID, err)
	}
	sths := appender.NewTrillian(static)
	// TODO: add mutations and mutator to admin.
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		log.Fatalf("Failed to create mutations object: %v", err)
	}
	mutator := entry.New()

	signer := signer.New(*domain, *mapID, tmap, *logID, sths, mutator, mutations, factory)
	go signer.StartSigning(context.Background(), *epochDuration)

	log.Printf("Signer started.")

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
