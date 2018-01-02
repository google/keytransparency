// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package main is a delegate server that can be used to
// (a) create user accounts.
// (b) update user accounts (that this server has created).
//
// The delegate server is desiged to be used by app operators
// to provision and update users before users take control over
// their own key management.
//
// The delegeate server may also be used to implement a third_party account
// reset provider service, should users wish to trust these providers will the
// ability to control and update thier accounts.
package main

import (
	"database/sql"
	"flag"
	"net/http"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/managementserver"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/keysets"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	pb "github.com/google/keytransparency/core/api/usermanager/v1/usermanager_proto"
	_ "github.com/google/trillian/crypto/keys/der/proto"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	addr         = flag.String("addr", ":8080", "The ip:port combination to listen on")
	metricsAddr  = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
	serverDBPath = flag.String("db", "test:zaphod@tcp(localhost:3306)/test", "Database connection string")
	keyFile      = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile     = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")

	instance = flag.Int64("instance", 0, "Instance number. Typically 0.")
)

func openDB() (*sql.DB, error) {
	db, err := sql.Open(engine.DriverName, *serverDBPath)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}

func main() {
	flag.Parse()

	// Connect to database.
	sqldb, err := openDB()
	if err != nil {
		glog.Exitf("Failed opening database: %v", err)
	}
	defer sqldb.Close()

	keysetdb, err := keysets.New(sqldb)
	if err != nil {
		glog.Exitf("Failed to create keyset table: %v", err)
	}

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	// Create gRPC server.
	svr := managementserver.New(*instance, keysetdb)
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)
	pb.RegisterUserManagerServiceServer(grpcServer, svr)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)

	// Create HTTP handlers and gRPC gateway.
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	gwmux, err := serverutil.GrpcGatewayMux(*addr, tcreds,
		pb.RegisterUserManagerServiceHandlerFromEndpoint)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	// Insert handlers for other http paths here.
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)

	metricMux := http.NewServeMux()
	metricMux.Handle("/metrics", promhttp.Handler())
	go func() {
		glog.Infof("Hosting metrics on %v", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, metricMux); err != nil {
			glog.Exitf("ListenAndServeTLS(%v): %v", *metricsAddr, err)
		}
	}()
	// Serve HTTP over TLS.
	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		serverutil.GrpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}
