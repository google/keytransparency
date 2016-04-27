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
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/e2e-key-server/signer"
	"github.com/google/e2e-key-server/appender/chain"
	"github.com/google/e2e-key-server/db/queue"
	"github.com/google/e2e-key-server/mutator/entry"
	"github.com/google/e2e-key-server/tree/sparse/sqlhist"

	"github.com/coreos/etcd/clientv3"
	_ "github.com/mattn/go-sqlite3"
)

var (
	serverDBPath  = flag.String("db-path", "db", "path/to/server/db where the local database will be created/opened.")
	epochDuration = flag.Uint("epoch-duration", 60, "Epoch advancement duration")
	mapID         = flag.String("map-id", "domain", "Domain for user identifiers.")
	etcdEndpoints = flag.String("etcd-endpoints", "localhost:2379, localhost:22379, localhost:32379", "Comma delimited list of etcd endpoints")
)

func openDB() *sql.DB {
	db, err := sql.Open("sqlite3", *serverDBPath)
	if err != nil {
		log.Fatalf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db.Ping(): %v", err)
	}
	return db
}

func openEtcd() *clientv3.Client {
	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   strings.Split(*etcdEndpoints, ","),
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect to etcd: %v", err)
	}
	return cli
}

func main() {
	flag.Parse()

	sqldb := openDB()
	defer sqldb.Close()
	etcdCli := openEtcd()
	defer etcdCli.Close()

	queue := queue.New(etcdCli, *mapID)
	tree := sqlhist.New(sqldb, *mapID)
	mutator := entry.New()
	appender := chain.New()

	signer := signer.New(queue, tree, mutator, appender)
	go signer.StartSequencing()
	go signer.StartSigning(time.Duration(*epochDuration) * time.Second)

	log.Printf("Signer started.")

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
