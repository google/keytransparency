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
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mapserver"
	"github.com/google/keytransparency/core/mutator/entry"
	ctxn "github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/impl/google/authentication"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/sql/sequenced"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"
	"github.com/google/trillian"

	"github.com/golang/protobuf/jsonpb"
	"github.com/golang/protobuf/proto"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	pb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
)

var (
	addr         = flag.String("addr", ":8080", "The ip:port combination to listen on")
	serverDBPath = flag.String("db", "db", "Database connection string")
	realm        = flag.String("auth-realm", "registered-users@gmail.com", "Authentication realm for WWW-Authenticate response header")
	vrfPath      = flag.String("vrf", "private_vrf_key.dat", "Path to VRF private key")
	keyFile      = flag.String("key", "testdata/server.key", "TLS private key file")
	certFile     = flag.String("cert", "testdata/server.pem", "TLS cert file")
	verbose      = flag.Bool("verbose", false, "Log requests and responses")

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
		log.Fatalf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db.Ping(): %v", err)
	}
	return db
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
	if err := pb.RegisterKeyTransparencyServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
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

var marshaler = jsonpb.Marshaler{Indent: "  ", OrigName: true}
var requestCounter uint64

// jsonLogger logs the request and response protobufs as json objects.
func jsonLogger(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp interface{}, err error) {
	atomic.AddUint64(&requestCounter, 1)
	// Print request.
	pb, ok := req.(proto.Message)
	if !ok {
		log.Printf("req %t, %v, not a proto.Message", req, req)
		return handler(ctx, req)
	}
	s, err := marshaler.MarshalToString(pb)
	if err != nil {
		log.Printf("Failed to marshal %v", pb)
		return handler(ctx, req)
	}
	log.Printf("%v>%v", requestCounter, s)

	resp, err = handler(ctx, req)

	// Print response.
	pb, ok = resp.(proto.Message)
	if !ok {
		log.Printf("req %t, %v, not a proto.Message", req, req)
		return resp, err
	}
	s, err = marshaler.MarshalToString(pb)
	if err != nil {
		log.Printf("Failed to marshal %v", pb)
		return resp, err
	}
	log.Printf("%v<%v", requestCounter, s)

	return resp, err
}

func newReadonlyMapServer(ctx context.Context, mapID int64, sqldb *sql.DB, factory ctxn.Factory) (trillian.TrillianMapClient, error) {
	tree, err := sqlhist.New(ctx, mapID, factory)
	if err != nil {
		return nil, fmt.Errorf("Failed to create SQL history: %v", err)
	}
	sths, err := sequenced.New(sqldb, mapID)
	if err != nil {
		return nil, fmt.Errorf("sequenced.New(%v): %v", mapID, err)
	}
	return mapserver.NewReadonly(mapID, tree, factory, sths), nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	// Open Resources.
	sqldb := openDB()
	defer sqldb.Close()
	factory := transaction.NewFactory(sqldb)

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load server credentials %v", err)
	}
	auth, err := authentication.NewGoogleAuth()
	if err != nil {
		log.Fatalf("Failed to create authentication library instance: %v", err)
	}

	// Create database and helper objects.
	commitments, err := commitments.New(sqldb, *mapID)
	if err != nil {
		log.Fatalf("Failed to create committer: %v", err)
	}
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		log.Fatalf("Failed to create mutations object: %v", err)
	}
	vrfPriv := openVRFKey()
	mutator := entry.New()

	// Connect to log server.
	tconn, err := grpc.Dial(*logURL)
	if err != nil {
		log.Fatalf("grpc.Dial(%v): %v", *logURL, err)
	}
	tlog := trillian.NewTrillianLogClient(tconn)

	// Connect to map server.
	var tmap trillian.TrillianMapClient
	if *mapURL != "" {
		mconn, err := grpc.Dial(*mapURL)
		if err != nil {
			log.Fatalf("grpc.Dial(%v): %v", *mapURL, err)
		}
		tmap = trillian.NewTrillianMapClient(mconn)
	} else {
		// Create an in-process readonly mapserver.
		tmap, err = newReadonlyMapServer(context.Background(), *mapID, sqldb, factory)
		if err != nil {
			log.Fatalf("newReadonlyMapServer(): %v", err)
		}
	}

	// Create gRPC server.
	svr := keyserver.New(*logID, tlog, *mapID, tmap, commitments,
		vrfPriv, mutator, auth, factory, mutations)
	opts := []grpc.ServerOption{grpc.Creds(creds)}
	if *verbose {
		opts = append(opts, grpc.UnaryInterceptor(jsonLogger))
	}
	grpcServer := grpc.NewServer(opts...)
	pb.RegisterKeyTransparencyServiceServer(grpcServer, svr)
	reflection.Register(grpcServer)

	// Create HTTP handlers and gRPC gateway.
	gwmux, err := grpcGatewayMux(*addr)
	if err != nil {
		log.Fatalf("Failed setting up REST proxy: %v", err)
	}

	mux := http.NewServeMux()
	// Insert handlers for other http paths here.
	mux.Handle("/", gwmux)

	// Serve HTTP2 server over TLS.
	log.Printf("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		grpcHandlerFunc(grpcServer, mux)); err != nil {
		log.Fatalf("ListenAndServeTLS: %v", err)
	}
}
