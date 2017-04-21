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
	"io/ioutil"
	"log"
	"sync"
	"time"

	"github.com/google/keytransparency/core/admin"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/signer"
	"github.com/google/keytransparency/impl/config"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"

	"golang.org/x/net/context"
)

var (
	serverDBPath  = flag.String("db", "db", "Database connection string")
	domain        = flag.String("domain", "example.com", "Distinguished name for this key server")
	mapID         = flag.Int64("map-id", 0, "ID for backend map")
	signingKey    = flag.String("key", "", "Path to private key PEM for STH signing")
	epochDuration = flag.Duration("period", time.Second*60, "Time between epoch creation")

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

func openPrivateKey() signatures.Signer {
	pem, err := ioutil.ReadFile(*signingKey)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", *signingKey, err)
	}
	sig, err := factory.NewSignerFromPEM(pem)
	if err != nil {
		log.Fatalf("Failed to create signer: %v", err)
	}
	return sig
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb, nil)

	// Create signer helper objects.
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		log.Fatalf("Failed to create mutations object: %v", err)
	}
	tree, err := sqlhist.New(context.Background(), *mapID, factory)
	if err != nil {
		log.Fatalf("Failed to create SQL history: %v", err)
	}
	mutator := entry.New()
	tlog, err := config.LogClient(*logID, *logURL, *logPubKey)
	if err != nil {
		log.Fatalf("LogClient(%v, %v, %v): %v", *logID, *logURL, *logPubKey, err)
	}
	static := admin.NewStatic()
	if err := static.AddLog(*mapID, tlog); err != nil {
		log.Fatalf("static.AddLog(%v): %v", *mapID, err)
	}
	sths := appender.NewTrillian(static)

	signer := signer.New(*domain, tree, mutator, sths, mutations, openPrivateKey(), factory)
	go signer.StartSigning(context.Background(), *epochDuration)

	log.Printf("Signer started.")

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
