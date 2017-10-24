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
	"context"
	"database/sql"
	"flag"
	"time"

	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"google.golang.org/grpc"

	_ "github.com/google/trillian/merkle/objhasher" // Register objhasher
)

var (
	serverDBPath     = flag.String("db", "db", "Database connection string")
	minEpochDuration = flag.Duration("min-period", time.Second*60, "Minimum time between epoch creation (create epochs only if there where mutations). Expected to be smaller than max-period.")
	maxEpochDuration = flag.Duration("max-period", time.Hour*12, "Maximum time between epoch creation (independent from mutations). This value should about half the time guaranteed by the policy.")

	// Info to connect to the trillian map and log.
	mapID  = flag.Int64("map-id", 0, "ID for backend map")
	mapURL = flag.String("map-url", "", "URL of Trilian Map Server")
	logID  = flag.Int64("log-id", 0, "Trillian Log ID")
	logURL = flag.String("log-url", "", "URL of Trillian Log Server for Signed Map Heads")
)

func openDB() *sql.DB {
	db, err := sql.Open(engine.DriverName, *serverDBPath)
	if err != nil {
		glog.Exitf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		glog.Exitf("db.Ping(): %v", err)
	}
	return db
}

func main() {
	flag.Parse()

	// Flag validation.
	if *maxEpochDuration < *minEpochDuration {
		glog.Exitf("maxEpochDuration < minEpochDuration: %v < %v, want maxEpochDuration >= minEpochDuration")
	}

	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb)

	// Connect to map server.
	mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	tmap := trillian.NewTrillianMapClient(mconn)

	// Connection to append only log
	lconn, err := grpc.Dial(*logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("Failed to connect to %v: %v", *logURL, err)
	}
	tlog := trillian.NewTrillianLogClient(lconn)

	// TODO: add mutations and mutator to admin.
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}
	mutator := entry.New()

	signer := sequencer.New(*mapID, tmap, *logID, tlog, mutator, mutations, factory)
	glog.Infof("Signer starting")
	go signer.StartSigning(context.Background(), *minEpochDuration, *maxEpochDuration)

	run(nil)
	glog.Errorf("Signer exiting")
}
