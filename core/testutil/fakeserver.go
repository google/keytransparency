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

	"google.golang.org/grpc"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// FakeKT runs a fake KeyTransparency server.
type FakeKT struct {
	Server pb.KeyTransparencyServer
	Client pb.KeyTransparencyClient
	Addr   string
}

// NewFakeKT returns a new fake Key Transparency server listening on a random port.
// Returns the started server and a close function.
func NewFakeKT(ktServer pb.KeyTransparencyServer) (*FakeKT, func(), error) {
	grpcServer := grpc.NewServer()
	pb.RegisterKeyTransparencyServer(grpcServer, ktServer)

	lis, err := net.Listen("tcp", "localhost:0")
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

	return &FakeKT{
		Server: ktServer,
		Client: pb.NewKeyTransparencyClient(cc),
		Addr:   lis.Addr().String(),
	}, stopFn, nil
}
