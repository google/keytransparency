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

	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/sql/adminstorage"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutationstorage"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	"google.golang.org/grpc"

	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	_ "github.com/google/trillian/merkle/objhasher" // Register objhasher
)

var (
	serverDBPath = flag.String("db", "db", "Database connection string")

	// Info to connect to the trillian map and log.
	mapURL = flag.String("map-url", "", "URL of Trilian Map Server")
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

	// Connect to trillian log and map backends.
	mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	lconn, err := grpc.Dial(*logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("Failed to connect to %v: %v", *logURL, err)
	}
	tlog := trillian.NewTrillianLogClient(lconn)
	tmap := trillian.NewTrillianMapClient(mconn)
	tadmin := trillian.NewTrillianAdminClient(mconn)

	// Database tables
	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb)

	mutations, err := mutationstorage.New(sqldb)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}
	adminStorage, err := adminstorage.New(sqldb)
	if err != nil {
		glog.Exitf("Failed to create adminstorage object: %v", err)
	}

	// Create servers
	signer := sequencer.New(adminStorage, tmap, tlog, entry.New(), mutations, factory)
	keygen := func(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
		return der.NewProtoFromSpec(spec)
	}
	adminServer := adminserver.New(adminStorage, tadmin, keygen)
	glog.Infof("Signer starting")

	// Run servers
	ctx := context.Background()
	signer.StartSequencingAll(ctx)
	run(adminServer)

	glog.Errorf("Signer exiting")
}
