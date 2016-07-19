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
	"net/http"
	"strings"
	"time"

	"github.com/google/key-transparency/appender"
	"github.com/google/key-transparency/authentication"
	"github.com/google/key-transparency/commitments"
	"github.com/google/key-transparency/keyserver"
	"github.com/google/key-transparency/mutator/entry"
	"github.com/google/key-transparency/queue"
	"github.com/google/key-transparency/tree/sparse/sqlhist"
	"github.com/google/key-transparency/vrf"
	"github.com/google/key-transparency/vrf/p256"

	"github.com/coreos/etcd/clientv3"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	_ "github.com/mattn/go-sqlite3" // Set database engine.
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/google/key-transparency/proto/security_e2ekeys_v1"
)

var (
	port          = flag.Int("port", 8080, "TCP port to listen on")
	serverDBPath  = flag.String("db", "db", "Database connection string")
	etcdEndpoints = flag.String("etcd", "", "Comma delimited list of etcd endpoints")
	mapID         = flag.String("domain", "example.com", "Distinguished name for this key server")
	realm         = flag.String("auth-realm", "registered-users@gmail.com", "Authentication realm for WWW-Authenticate response header")
	vrfPath       = flag.String("vrf", "private_vrf_key.dat", "Path to VRF private key")
	mapLogURL     = flag.String("maplog", "", "URL of CT server for Signed Map Heads")
	keyFile       = flag.String("key", "testdata/server.key", "TLS private key file")
	certFile      = flag.String("cert", "testdata/server.pem", "TLS cert file")
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
	vrfPriv, err := p256.NewVRFSignerFromPEM(vrfBytes)
	if err != nil {
		log.Fatalf("Failed parsing VRF private key: %v", err)
	}
	return vrfPriv
}

func grpcGatewayMux(addr string) (*runtime.ServeMux, error) {
	ctx := context.Background()

	creds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		return nil, err
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	gwmux := runtime.NewServeMux()
	if err := pb.RegisterE2EKeyServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
		return nil, err
	}

	return gwmux, nil
}

// grpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func grpcHandlerFunc(grpcServer *grpc.Server, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a partial recreation of gRPC's internal checks.
		// https://github.com/grpc/grpc-go/blob/master/transport/handler_server.go#L62
		if r.ProtoMajor == 2 && strings.Contains(r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// Main runs a key transparency front end for gRPC and REST APIS.
func Main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	// Open Resources.
	sqldb := openDB()
	defer sqldb.Close()
	etcdCli := openEtcd()
	defer etcdCli.Close()

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load server credentials %v", err)
	}
	auth, err := authentication.NewGoogleAuth()
	if err != nil {
		log.Fatalf("Failed to load authentication library: %v", err)
	}

	// Create database and helper objects.
	commitments := commitments.New(sqldb, *mapID)
	queue := queue.New(etcdCli, *mapID)
	tree := sqlhist.New(sqldb, *mapID)
	sths := appender.New(sqldb, *mapID, *mapLogURL)
	vrfPriv := openVRFKey()
	mutator := entry.New()

	// Create gRPC server.
	svr := keyserver.New(commitments, queue, tree, sths, vrfPriv, mutator, auth)
	grpcServer := grpc.NewServer(grpc.Creds(creds))
	pb.RegisterE2EKeyServiceServer(grpcServer, svr)

	// Create HTTP handlers and gRPC gateway.
	addr := fmt.Sprintf("localhost:%d", *port)
	gwmux, err := grpcGatewayMux(addr)
	if err != nil {
		log.Fatalf("Failed setting up REST proxy: %v", err)
	}

	mux := http.NewServeMux()
	// Insert handlers for other http paths here.
	mux.Handle("/", gwmux)

	// Serve HTTP2 server over TLS.
	log.Printf("Listening on %v", addr)
	if err := http.ListenAndServeTLS(addr, *certFile, *keyFile,
		grpcHandlerFunc(grpcServer, mux)); err != nil {
		log.Fatalf("ListenAndServeTLS: ", err)
	}
}
