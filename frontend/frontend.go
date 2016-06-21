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

package frontend

import (
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/mutator/entry"
	"github.com/google/e2e-key-server/proxy"
	"github.com/google/e2e-key-server/queue"
	"github.com/google/e2e-key-server/tree/sparse/sqlhist"
	"github.com/google/e2e-key-server/vrf"
	"github.com/google/e2e-key-server/vrf/p256"

	"github.com/coreos/etcd/clientv3"
	"github.com/gengo/grpc-gateway/runtime"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	v1pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

var (
	grpcPort      = flag.Int("port", 8080, "TCP port to listen on")
	httpPort      = flag.Int("http_port", 8081, "TCP port to listen on")
	serverDBPath  = flag.String("db", "db", "Database connection string")
	etcdEndpoints = flag.String("etcd", "", "Comma delimited list of etcd endpoints")
	mapID         = flag.String("domain", "example.com", "Distinguished name for this key server")
	realm         = flag.String("auth-realm", "registered-users@gmail.com", "Authentication realm for WWW-Authenticate response header")
	vrfPath       = flag.String("vrf", "private_vrf_key.dat", "Path to VRF private key")
	mapLogURL     = flag.String("maplog", "", "URL of CT server for Signed Map Heads")
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

func openVRFKey() vrf.PrivateKey {
	vrfBytes, err := ioutil.ReadFile(*vrfPath)
	if err != nil {
		log.Fatalf("Failed opening VRF private key: %v", err)
	}
	vrfPriv, err := p256.ParsePrivateKey(vrfBytes)
	if err != nil {
		log.Fatalf("Failed parsing VRF private key: %v", err)
	}
	return vrfPriv
}

func runRestProxy(grpcPort, httpPort int) error {
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	grpcEndpoint := fmt.Sprintf("localhost:%d", grpcPort)
	mux := runtime.NewServeMux()
	opts := []grpc.DialOption{grpc.WithInsecure()}
	if err := v1pb.RegisterE2EKeyProxyHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return err
	}
	if err := v2pb.RegisterE2EKeyServiceHandlerFromEndpoint(ctx, mux, grpcEndpoint, opts); err != nil {
		return err
	}

	log.Printf("http proxy server listening on port %v", httpPort)
	http.ListenAndServe(fmt.Sprintf(":%d", httpPort), mux)
	return nil
}

func Main() {
	flag.Parse()

	sqldb := openDB()
	defer sqldb.Close()
	etcdCli := openEtcd()
	defer etcdCli.Close()

	commitments := commitments.New(sqldb, *mapID)
	queue := queue.New(etcdCli, *mapID)
	tree := sqlhist.New(sqldb, *mapID)
	appender := appender.New(sqldb, *mapID, *mapLogURL)
	vrfPriv := openVRFKey()
	mutator := entry.New()

	v2 := keyserver.New(commitments, queue, tree, appender, vrfPriv, mutator)
	v1 := proxy.New(v2)

	grpcServer := grpc.NewServer()
	v2pb.RegisterE2EKeyServiceServer(grpcServer, v2)
	v1pb.RegisterE2EKeyProxyServer(grpcServer, v1)

	// TODO: fetch private TLS key from repository.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	log.Printf("gRPC server listening on port %v", *grpcPort)
	go grpcServer.Serve(lis)

	log.Fatal("Server exiting with: %v", runRestProxy(*grpcPort, *httpPort))
}
