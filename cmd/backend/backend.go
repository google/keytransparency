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
	"crypto/rand"
	"database/sql"
	"flag"
	"io/ioutil"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/key-transparency/appender"
	"github.com/google/key-transparency/mutator/entry"
	"github.com/google/key-transparency/queue"
	"github.com/google/key-transparency/signatures"
	"github.com/google/key-transparency/signer"
	"github.com/google/key-transparency/tree/sparse/sqlhist"

	"github.com/coreos/etcd/clientv3"
	_ "github.com/mattn/go-sqlite3"
)

var (
	serverDBPath  = flag.String("db", "db", "Database connection string")
	etcdEndpoints = flag.String("etcd", "", "Comma delimited list of etcd endpoints")
	epochDuration = flag.Uint("period", 60, "Seconds between epoch creation")
	mapID         = flag.String("domain", "example.com", "Distinguished name for this key server")
	mapLogURL     = flag.String("maplog", "", "URL of CT server for Signed Map Heads")
	signingKey    = flag.String("key", "", "Path to private key PEM for STH signing")
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

func openPrivateKey() *signatures.Signer {
	pem, err := ioutil.ReadFile(*signingKey)
	if err != nil {
		log.Fatalf("Failed to read file %v: %v", *signingKey, err)
	}
	key, _, err := signatures.PrivateKeyFromPEM(pem)
	if err != nil {
		log.Fatalf("Read to read private key: %v", err)
	}
	sig, err := signatures.NewSigner(rand.Reader, key)
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
	etcdCli := openEtcd()
	defer etcdCli.Close()

	queue := queue.New(etcdCli, *mapID)
	tree, err := sqlhist.New(sqldb, *mapID)
	if err != nil {
		log.Fatalf("Failed to create SQL history: %v", err)
	}
	mutator := entry.New()
	sths, err := appender.New(sqldb, *mapID, *mapLogURL)
	if err != nil {
		log.Fatalf("Failed to create STH appender: %v", err)
	}
	mutations, err := appender.New(sqldb, *mapID, *mapLogURL)
	if err != nil {
		log.Fatalf("Failed to create mutation appender: %v", err)
	}

	signer := signer.New(*mapID, queue, tree, mutator, sths, mutations, openPrivateKey())
	go signer.StartSequencing()
	go signer.StartSigning(time.Duration(*epochDuration) * time.Second)

	log.Printf("Signer started.")

	var wg sync.WaitGroup
	wg.Add(1)
	wg.Wait()
}
