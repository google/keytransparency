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
	"context"
	"net"
	"net/http"

	"github.com/google/keytransparency/cmd/serverutil"

	"github.com/golang/glog"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

func serveHTTPMetric(port string) {
	metricMux := http.NewServeMux()
	metricMux.Handle("/metrics", promhttp.Handler())

	glog.Infof("Hosting metrics on %v", port)
	if err := http.ListenAndServe(port, metricMux); err != nil {
		glog.Fatalf("ListenAndServeTLS(%v): %v", *metricsAddr, err)
	}
}

func serveHTTPGateway(ctx context.Context, lis net.Listener, dopts []grpc.DialOption,
	grpcServer *grpc.Server, services ...serverutil.RegisterServiceFromEndpoint) {
	// Wire up gRPC and HTTP servers.
	gwmux, err := serverutil.GrpcGatewayMux(ctx, lis.Addr().String(), dopts, services...)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle("/", gwmux)

	server := &http.Server{Handler: serverutil.GrpcHandlerFunc(grpcServer, mux)}
	if err := server.ServeTLS(lis, *certFile, *keyFile); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}
