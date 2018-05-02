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

package testutil

import (
	"net"

	"github.com/golang/mock/gomock"
	"github.com/google/keytransparency/core/testutil/ktmock"
	"google.golang.org/grpc"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// MockKT runs a mock KeyTransparency server.
type MockKT struct {
	Server *ktmock.MockKeyTransparencyServer
	Client pb.KeyTransparencyClient
	Addr   string
}

// NewMockKT returns a new mock Key Transparency server listening on a random port.
// Returns the started server and a close function.
func NewMockKT(ctrl *gomock.Controller) (*MockKT, func(), error) {
	grpcServer := grpc.NewServer()
	ktServer := ktmock.NewMockKeyTransparencyServer(ctrl)
	pb.RegisterKeyTransparencyServer(grpcServer, ktServer)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	go grpcServer.Serve(lis)

	cc, err := grpc.Dial(lis.Addr().String(), grpc.WithInsecure())
	if err != nil {
		grpcServer.Stop()
		lis.Close()
		return nil, nil, err
	}

	stopFn := func() {
		cc.Close()
		grpcServer.Stop()
		lis.Close()
	}

	return &MockKT{
		Server: ktServer,
		Client: pb.NewKeyTransparencyClient(cc),
		Addr:   lis.Addr().String(),
	}, stopFn, nil
}
