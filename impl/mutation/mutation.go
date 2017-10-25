// Copyright 2016 Google Inc. All Rights Reserved.
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

// Package mutation implements the mutations service a monitor can query.
package mutation

import (
	"context"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	cmutation "github.com/google/keytransparency/core/mutation"

	gpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

// Server holds internal state for the monitor server.
type Server struct {
	srv *cmutation.Server
}

// New creates a new instance of the monitor server.
func New(srv *cmutation.Server) *Server {
	return &Server{srv}
}

// GetMutations returns a list of mutations paged by epoch number.
func (s *Server) GetMutations(ctx context.Context, in *pb.GetMutationsRequest) (*pb.GetMutationsResponse, error) {
	return s.srv.GetMutations(ctx, in)
}

// GetMutationsStream is a streaming API similar to GetMutations.
func (s *Server) GetMutationsStream(in *pb.GetMutationsRequest, stream gpb.MutationService_GetMutationsStreamServer) error {
	return grpc.Errorf(codes.Unimplemented, "GetMutationsStream is unimplemented")
}
