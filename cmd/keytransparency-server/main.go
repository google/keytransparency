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
	"io/ioutil"
	"log"
	"net/http"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/mutation"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	cmutation "github.com/google/keytransparency/core/mutation"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	mpb "github.com/google/keytransparency/core/proto/mutation_v1_grpc"
	gauth "github.com/google/keytransparency/impl/google/authentication"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	addr         = flag.String("addr", ":8080", "The ip:port combination to listen on")
	metricsAddr  = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
	serverDBPath = flag.String("db", "test:zaphod@tcp(localhost:3306)/test", "Database connection string")
	vrfPath      = flag.String("vrf", "genfiles/vrf-key.pem", "Path to VRF private key")
	keyFile      = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile     = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")
	authType     = flag.String("auth-type", "google", "Sets the type of authentication required from clients to update their entries. Accepted values are google (oauth tokens) and insecure-fake (for testing only).")

	// Info to connect to sparse merkle tree database.
	mapID  = flag.Int64("map-id", 0, "ID for backend map")
	mapURL = flag.String("map-url", "", "URL of Trilian Map Server")

	// Info to send Signed Map Heads to a Trillian Log.
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

func openVRFKey() vrf.PrivateKey {
	vrfBytes, err := ioutil.ReadFile(*vrfPath)
	if err != nil {
		glog.Exitf("Failed opening VRF private key: %v", err)
	}
	vrfPriv, err := p256.NewVRFSignerFromPEM(vrfBytes)
	if err != nil {
		glog.Exitf("Failed parsing VRF private key: %v", err)
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
	if err := ktpb.RegisterKeyTransparencyServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
		return nil, err
	}
	if err := mpb.RegisterMutationServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
		return nil, err
	}

	return gwmux, nil
}

func main() {
	flag.Parse()

	// Open Resources.
	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb)

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	var auth authentication.Authenticator
	switch *authType {
	case "insecure-fake":
		glog.Warning("INSECURE! Using fake authentication.")
		auth = authentication.NewFake()
	case "google":
		var err error
		auth, err = gauth.NewGoogleAuth()
		if err != nil {
			glog.Exitf("Failed to create authentication library instance: %v", err)
		}
	default:
		glog.Exitf("Invalid auth-type parameter: %v.", *authType)
	}
	authz := authorization.New()

	// Create database and helper objects.
	commitments, err := commitments.New(sqldb, *mapID)
	if err != nil {
		glog.Exitf("Failed to create committer: %v", err)
	}
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}
	vrfPriv := openVRFKey()
	mutator := entry.New()

	// Connect to log server.
	tconn, err := grpc.Dial(*logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *logURL, err)
	}
	tlog := trillian.NewTrillianLogClient(tconn)

	// Connect to map server.
	mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	tmap := trillian.NewTrillianMapClient(mconn)
	tadmin := trillian.NewTrillianAdminClient(mconn)

	// Create gRPC server.
	svr := keyserver.New(*logID, tlog, *mapID, tmap, tadmin, commitments,
		vrfPriv, mutator, auth, authz, factory, mutations)
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)
	msrv := mutation.New(cmutation.New(*logID, *mapID, tlog, tmap, mutations, factory))
	ktpb.RegisterKeyTransparencyServiceServer(grpcServer, svr)
	mpb.RegisterMutationServiceServer(grpcServer, msrv)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	// Create HTTP handlers and gRPC gateway.
	gwmux, err := grpcGatewayMux(*addr)
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
