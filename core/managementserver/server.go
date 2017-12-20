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

// Package managementserver implements the user manager APIs
package managementserver

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
	pb "github.com/google/keytransparency/core/api/usermanager/v1/usermanager_proto"
	"github.com/google/keytransparency/core/storage"
)

// Server implements pb.UserManagerServiceServer
type Server struct {
	instance int64
	keysets  storage.KeySets
}

// New creates a new managementserver
func New() *Server {
	return &Server{}
}

// GetKeySet returns a list of public keys (a keyset) that corresponds to the signing keys
// this service has for a given domain and app.
func (s *Server) GetKeySet(ctx context.Context, in *pb.GetKeySetRequest) (*tpb.KeySet, error) {
	ks, err := s.keysets.Get(ctx, s.instance, in.GetDomainId(), in.GetAppId())
	if err != nil {
		return nil, err
	}
	ks.SigningKeys = nil // DON'T LEAK PRIVATE KEYS!!
	return ks, nil
}

// CreateUser creates a new user and initializes it.
// If the user already exists, this operation will fail.
func (s *Server) CreateUser(context.Context, *pb.CreateUserRequest) (*tpb.User, error) {
	return nil, status.Errorf(codes.Unimplemented, "unimplemented")
}

// UpdateUser sets the public key for an user.
func (s *Server) UpdateUser(context.Context, *pb.UpdateUserRequest) (*tpb.User, error) {
	return nil, status.Errorf(codes.Unimplemented, "unimplemented")
}

// BatchCreateUser creates a set of new users.
func (s *Server) BatchCreateUser(context.Context, *pb.BatchCreateUserRequest) (*tpb.User, error) {
	return nil, status.Errorf(codes.Unimplemented, "unimplemented")
}
