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
	"net/http"
	"os"
	"os/signal"
	"strings"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gocloud.dev/server"
	"gocloud.dev/server/health"
	"google.golang.org/grpc"
)

// gRPCHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise.
func gRPCHandlerFunc(grpcServer http.Handler, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a partial recreation of gRPC's internal checks.
		// https://github.com/grpc/grpc-go/blob/v1.26.0/internal/transport/handler_server.go#L62
		if r.ProtoMajor == 2 && strings.HasPrefix(
			r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// RegisterServiceFromConn registers services with a grpc server's ServeMux
type RegisterServiceFromConn func(context.Context, *runtime.ServeMux, *grpc.ClientConn) error

// GRPCGatewayServer returns a server for given services over HTTP / JSON and gRPC.
func GRPCGatewayServer(ctx context.Context,
	grpcServer *grpc.Server, conn *grpc.ClientConn,
	services ...RegisterServiceFromConn) (*http.Server, error) {
	// Wire up gRPC and HTTP servers.

	gwmux := runtime.NewServeMux()
	for _, s := range services {
		if err := s(ctx, gwmux, conn); err != nil {
			return nil, err
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/", RootHealthHandler(gwmux))
	return &http.Server{Handler: gRPCHandlerFunc(grpcServer, mux)}, nil
}

// MetricsServer returns server with monitoring APIs
func MetricsServer(addr string, opts *server.Options) *server.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.Handle("/", http.HandlerFunc(health.HandleLive))

	glog.Infof("Hosting server status and metrics on %v", addr)
	return server.New(mux, opts)
}

// ListenForCtrlC gracefully stops all the servers on an interrupt signal.
func ListenForCtrlC(servers ...interface{ Shutdown(context.Context) error }) {
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)
	// Receive off the chanel in a loop, because the interrupt could be sent
	// before ListenAndServe starts.
	for {
		<-interrupt
		for _, svr := range servers {
			if err := svr.Shutdown(context.Background()); err != nil {
				glog.Errorf("Shutdown: %v", err)
			}
		}
	}
}
