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

package serverutil

import (
	"context"
	"net/http"
	"strings"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"google.golang.org/grpc"
)

// GrpcHandlerFunc returns an http.Handler that delegates to grpcServer on incoming gRPC
// connections or otherHandler otherwise. Copied from cockroachdb.
func GrpcHandlerFunc(grpcServer http.Handler, otherHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// This is a partial recreation of gRPC's internal checks.
		// https://github.com/grpc/grpc-go/blob/master/transport/handler_server.go#L62
		if r.ProtoMajor == 2 && strings.HasPrefix(
			r.Header.Get("Content-Type"), "application/grpc") {
			grpcServer.ServeHTTP(w, r)
		} else {
			otherHandler.ServeHTTP(w, r)
		}
	})
}

// RegisterServiceFromEndpoint registers services with a grpc server's ServeMux
type RegisterServiceFromEndpoint func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error

// GrpcGatewayMux registers multiple gRPC services with a gRPC ServeMux
func GrpcGatewayMux(ctx context.Context, addr string, dopts []grpc.DialOption,
	services ...RegisterServiceFromEndpoint) (*runtime.ServeMux, error) {

	gwmux := runtime.NewServeMux()
	for _, s := range services {
		if err := s(ctx, gwmux, addr, dopts); err != nil {
			return nil, err
		}
	}

	return gwmux, nil
}
