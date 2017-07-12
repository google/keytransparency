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
	"flag"
	"net"
	"net/http"
	"strings"
	"time"

	mopb "github.com/google/keytransparency/impl/proto/monitor_v1_service"
	mupb "github.com/google/keytransparency/impl/proto/mutation_v1_service"

	"github.com/golang/glog"
	"github.com/google/keytransparency/impl/monitor"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"
)

var (
	addr      = flag.String("addr", ":8099", "The ip:port combination to listen on")
	keyFile   = flag.String("key", "genfiles/server.key", "TLS private key file")
	certFile  = flag.String("cert", "genfiles/server.pem", "TLS cert file")

	pollPeriod = flag.Duration("poll-period", time.Second*5, "Maximum time between polling the key-server. Ideally, this is equal to the min-period of paramerter of the keyserver.")
	ktURL      = flag.String("kt-url", "localhost:8080", "URL of key-server.")
	ktPEM      = flag.String("kt-key", "genfiles/server.crt", "Path to kt-server's public key")
	// TODO(ismail): are the IDs actually needed for verification operations?
	mapID = flag.Int64("map-id", 0, "Trillian map ID")
	logID = flag.Int64("log-id", 0, "Trillian Log ID")

	// TODO(ismail): expose prometheus metrics: a variable that tracks valid/invalid MHs
	metricsAddr = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
)

func grpcGatewayMux(addr string) (*runtime.ServeMux, error) {
	ctx := context.Background()
	creds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		return nil, err
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	gwmux := runtime.NewServeMux()
	if err := mopb.RegisterMonitorServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
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

func main() {
	flag.Parse()

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	// Create gRPC server.
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)

	// Connect to the kt-server's mutation API:
	grpcc, err := dial(*ktURL, *ktPEM)
	if err != nil {
		glog.Fatalf("Error Dialing %v: %v", ktURL, err)
	}
	mcc := mupb.NewMutationServiceClient(grpcc)

	srv := monitor.New(mcc, *mapID, *pollPeriod)

	mopb.RegisterMonitorServiceServer(grpcServer, srv)
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

	go func() {
		if err := srv.StartPolling(); err != nil {
			glog.Fatalf("Could not start polling mutations.")
		}
	}()

	// Serve HTTP2 server over TLS.
	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		grpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}

func dial(ktURL, caFile string) (*grpc.ClientConn, error) {
	var opts []grpc.DialOption
	host, _, err := net.SplitHostPort(ktURL)
	if err != nil {
		return nil, err
	}
	var creds credentials.TransportCredentials
	if caFile != "" {
		var err error
		creds, err = credentials.NewClientTLSFromFile(caFile, host)
		if err != nil {
			return nil, err
		}
	} else {
		// Use the local set of root certs.
		creds = credentials.NewClientTLSFromCert(nil, host)
	}
	opts = append(opts, grpc.WithTransportCredentials(creds))

	// TODO(ismail): authenticate the monitor to the kt-server:
	cc, err := grpc.Dial(ktURL, opts...)
	if err != nil {
		return nil, err
	}
	return cc, nil
}
