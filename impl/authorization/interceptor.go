// Copyright 2018 Google Inc. All Rights Reserved.
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

package authorization

import (
	"context"

	"google.golang.org/grpc"

	"github.com/golang/glog"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

// AuthPair defines an authentication and authorization pair.
type AuthPair struct {
	AuthnFunc grpc_auth.AuthFunc
	AuthzFunc AuthzFunc
}

// UnaryServerInterceptor returns a new unary server interceptor that performs per-request auth.
func UnaryServerInterceptor(authFuncs map[string]AuthPair) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		policy, ok := authFuncs[info.FullMethod]
		if !ok {
			glog.V(4).Infof("auth interceptor: no handler for %v", info.FullMethod)
			// If no auth handler was found for this method, invoke the method directly.
			return handler(ctx, req)
		}
		newCtx, err := policy.AuthnFunc(ctx)
		if err != nil {
			return nil, err
		}
		if err := policy.AuthzFunc(newCtx, req); err != nil {
			return nil, err
		}
		return handler(newCtx, req)
	}
}

// StreamServerInterceptor returns a new stream server interceptor that performs per-request auth.
func StreamServerInterceptor(authFuncs map[string]AuthPair) grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		policy, ok := authFuncs[info.FullMethod]
		if !ok {
			glog.V(2).Infof("auth interceptor: no handler for %v", info.FullMethod)
			// If no auth handler was found for this method, invoke the method directly.
			return handler(srv, stream)
		}

		newCtx, err := policy.AuthnFunc(stream.Context())
		if err != nil {
			return err
		}
		if err := policy.AuthzFunc(newCtx, stream); err != nil {
			return err
		}
		wrapped := grpc_middleware.WrapServerStream(stream)
		wrapped.WrappedContext = newCtx
		return handler(srv, wrapped)
	}
}
