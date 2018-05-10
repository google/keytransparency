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
	"net/http"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/sql/domain"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutationstorage"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/grpc-ecosystem/go-grpc-middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	_ "github.com/google/trillian/crypto/keys/der/proto"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	addr         = flag.String("addr", ":8080", "The ip:port combination to listen on")
	metricsAddr  = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
	serverDBPath = flag.String("db", "test:zaphod@tcp(localhost:3306)/test", "Database connection string")
	keyFile      = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile     = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")
	authType     = flag.String("auth-type", "google", "Sets the type of authentication required from clients to update their entries. Accepted values are google (oauth tokens) and insecure-fake (for testing only).")

	mapURL = flag.String("map-url", "", "URL of Trillian Map Server")
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

	// Open Resources.
	sqldb := openDB()
	defer sqldb.Close()

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	var authFunc grpc_auth.AuthFunc
	switch *authType {
	case "insecure-fake":
		glog.Warning("INSECURE! Using fake authentication.")
		authFunc = authentication.FakeAuthFunc
	case "google":
		var err error
		gauth, err := authentication.NewGoogleAuth()
		if err != nil {
			glog.Exitf("Failed to create authentication library instance: %v", err)
		}
		authFunc = gauth.AuthFunc
	default:
		glog.Exitf("Invalid auth-type parameter: %v.", *authType)
	}
	authz := authorization.New()

	// Create database and helper objects.
	domains, err := domain.NewStorage(sqldb)
	if err != nil {
		glog.Exitf("Failed to create domain storage: %v", err)
	}
	mutations, err := mutationstorage.New(sqldb)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}

	// Connect to log and map server.
	tconn, err := grpc.Dial(*logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *logURL, err)
	}
	mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	tlog := trillian.NewTrillianLogClient(tconn)
	tmap := trillian.NewTrillianMapClient(mconn)
	logAdmin := trillian.NewTrillianAdminClient(tconn)
	mapAdmin := trillian.NewTrillianAdminClient(mconn)

	// Create gRPC server.
	queue := mutator.MutationQueue(mutations)
	ksvr := keyserver.New(tlog, tmap, logAdmin, mapAdmin,
		entry.New(), authz, domains, queue, mutations)
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_prometheus.StreamServerInterceptor,
			grpc_auth.StreamServerInterceptor(authFunc),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_prometheus.UnaryServerInterceptor,
			grpc_auth.UnaryServerInterceptor(authFunc),
		)),
	)
	pb.RegisterKeyTransparencyServer(grpcServer, ksvr)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	// Create HTTP handlers and gRPC gateway.
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	gwmux, err := serverutil.GrpcGatewayMux(*addr, tcreds,
		pb.RegisterKeyTransparencyHandlerFromEndpoint)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	// Insert handlers for other http paths here.
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)

	metricMux := http.NewServeMux()
	metricMux.Handle("/metrics", promhttp.Handler())
	go func() {
		log.Printf("Hosting metrics on %v", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, metricMux); err != nil {
			log.Fatalf("ListenAndServeTLS(%v): %v", *metricsAddr, err)
		}
	}()
	// Serve HTTP2 server over TLS.
	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		serverutil.GrpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}
