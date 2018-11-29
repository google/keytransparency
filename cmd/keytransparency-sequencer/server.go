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
	"net/http"

	"github.com/google/keytransparency/cmd/serverutil"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func startHTTPServer(grpcServer *grpc.Server, addr string,
	services ...serverutil.RegisterServiceFromEndpoint) *http.Server {
	// Wire up gRPC and HTTP servers.
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	gwmux, err := serverutil.GrpcGatewayMux(addr, tcreds, services...)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)

	metricMux := http.NewServeMux()
	metricMux.Handle("/metrics", promhttp.Handler())
	go func() {
		glog.Infof("Hosting metrics on %v", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, metricMux); err != nil {
			glog.Fatalf("ListenAndServeTLS(%v): %v", *metricsAddr, err)
		}
	}()

	server := &http.Server{
		Addr:    addr,
		Handler: serverutil.GrpcHandlerFunc(grpcServer, mux),
	}

	go func() {
		glog.Infof("Listening on %v", addr)
		if err := server.ListenAndServeTLS(*certFile, *keyFile); err != nil {
			glog.Errorf("ListenAndServeTLS: %v", err)
		}
	}()
	// Return a handle to the http server to callers can call Shutdown().
	return server
}
