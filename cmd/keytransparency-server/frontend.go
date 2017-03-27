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
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/vrf"
	"github.com/google/keytransparency/core/vrf/p256"
	"github.com/google/keytransparency/impl/etcd/queue"
	"github.com/google/keytransparency/impl/google/authentication"
	"github.com/google/keytransparency/impl/sql/appender"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/coreos/etcd/clientv3"
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
	addr          = flag.String("addr", ":8080", "The ip:port combination to listen on")
	serverDBPath  = flag.String("db", "db", "Database connection string")
	etcdEndpoints = flag.String("etcd", "", "Comma delimited list of etcd endpoints")
	mapID         = flag.Int64("mapid", 0, "ID for backend map")
	realm         = flag.String("auth-realm", "registered-users@gmail.com", "Authentication realm for WWW-Authenticate response header")
	vrfPath       = flag.String("vrf", "private_vrf_key.dat", "Path to VRF private key")
	mapLogURL     = flag.String("maplog", "", "URL of CT server for Signed Map Heads")
	keyFile       = flag.String("key", "testdata/server.key", "TLS private key file")
	certFile      = flag.String("cert", "testdata/server.pem", "TLS cert file")
	verbose       = flag.Bool("verbose", false, "Log requests and responses")
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

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	flag.Parse()

	// Open Resources.
	sqldb := openDB()
	defer sqldb.Close()
	etcdCli := openEtcd()
	defer etcdCli.Close()
	factory := transaction.NewFactory(sqldb, etcdCli)

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
	queue := queue.New(context.Background(), etcdCli, *mapID, factory)
	tree, err := sqlhist.New(context.Background(), sqldb, *mapID, factory)
	if err != nil {
		log.Fatalf("Failed to create SQL history: %v", err)
	}
	sths, err := appender.New(context.Background(), sqldb, *mapID, *mapLogURL, nil)
	if err != nil {
		log.Fatalf("Failed to create appender: %v", err)
	}
	vrfPriv := openVRFKey()
	mutator := entry.New()

	// Create gRPC server.
	svr := keyserver.New(commitments, queue, tree, sths, vrfPriv, mutator, auth, factory)
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
