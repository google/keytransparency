// Copyright 2020 Google Inc. All Rights Reserved.
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
	"net"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Listen binds to listenAddr and returns a gRPC connection to it.
func Listen(ctx context.Context, listenAddr, certFile string) (net.Listener, *grpc.ClientConn, func(), error) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, nil, nil, err
	}
	addr := lis.Addr().String()
	glog.Infof("Listening on %v", addr)

	// Non-blocking dial before we start the server.
	tcreds, err := credentials.NewClientTLSFromFile(certFile, "")
	if err != nil {
		return nil, nil, nil, err
	}
	conn, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(tcreds))
	if err != nil {
		return nil, nil, nil, err
	}
	return lis, conn, func() {
		if err := conn.Close(); err != nil {
			glog.Errorf("Failed to close connection: %v", err)
		}
	}, nil
}
