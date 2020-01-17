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

// Package serverutil provides helper functions to main.go files.
package serverutil

import (
	"context"
	"net"
	"net/http"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/grpc"
)

// RegisterServiceFromConn registers services with a grpc server's ServeMux
type RegisterServiceFromConn func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error

// ServeHTTPAPI serves the given services over HTTP / JSON.
func ServeHTTPAPI(ctx context.Context, lis net.Listener,
	conn *grpc.ClientConn, services ...RegisterServiceFromConn) error {
	gwmux := runtime.NewServeMux()
	for _, s := range services {
		if err := s(ctx, gwmux, conn); err != nil {
			return err
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", RootHealthHandler(gwmux))
	return http.Serve(lis, mux)
}

// ServeHTTPMetrics serves monitoring APIs
func ServeHTTPMetrics(addr string, ready http.HandlerFunc) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/healthz", Healthz())
	mux.Handle("/readyz", ready)
	mux.Handle("/", Healthz())

	glog.Infof("Hosting server status and metrics on %v", addr)
	return http.ListenAndServe(addr, mux)
}
