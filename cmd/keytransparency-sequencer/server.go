// Copyright 2017 Google Inc. All Rights Reserved.
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
	"net/http"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/google/keytransparency/cmd/serverutil"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	addr     = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
	keyFile  = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")
)

func run(svr ktpb.KeyTransparencyAdminServiceServer) {
	// Wire up gRPC and HTTP servers.
	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	gwmux, err := serverutil.GrpcGatewayMux(*addr, tcreds,
		ktpb.RegisterKeyTransparencyAdminServiceHandlerFromEndpoint)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", gwmux)

	ktpb.RegisterKeyTransparencyAdminServiceServer(grpcServer, svr)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		serverutil.GrpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}
