// Copyright 2015 Google Inc. All Rights Reserved.
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

// Package proxy converts v1 API requests into v2 API calls.
package proxy

import (
	"github.com/google/e2e-key-server/keyserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
)

// Server holds internal state for the proxy server.
type Server struct {
	s *keyserver.Server
}

// New creates a new instance of the proxy server.
func New(svr *keyserver.Server) *Server {
	return &Server{svr}
}

// GetUser returns a user's profile.
func (s *Server) GetUser(ctx context.Context, in *v2pb.GetUserRequest) (*v2pb.Profile, error) {
	result, err := s.s.GetUser(ctx, in)
	if err != nil {
		return nil, err
	}

	// Extract and returned the user profile from the resulted
	// EntryProfileAndProof.
	p := new(v2pb.Profile)
	if err := proto.Unmarshal(result.Profile, p); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Provided profile cannot be parsed")
	}

	return p, nil
}
