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

	keypb "github.com/google/keytransparency/core/proto/keymaster_proto"
	pb "github.com/google/keytransparency/core/proto/keytransparency/usermanager/v1/usermanager_proto"
	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

// Server implements pb.UserManagerServiceServer
type Server struct{}

// New creates a new managementserver
func New() *Server {
	return &Server{}
}

// GetKeySet returns a list of public keys (a keyset) that corresponds to the signing keys
// this service has for a given domain and app.
func (s *Server) GetKeySet(context.Context, *pb.GetKeySetRequest) (*keypb.KeySet, error) {
	panic("unimplemented")
}

// CreateUser creates a new user and initializes it.
// If the user already exists, this operation will fail.
func (s *Server) CreateUser(context.Context, *pb.CreateUserRequest) (*ktpb.User, error) {
	panic("unimplemented")
}

// UpdateUser sets the public key for an user.
func (s *Server) UpdateUser(context.Context, *pb.UpdateUserRequest) (*ktpb.User, error) {
	panic("unimplemented")
}

// BatchCreateUser creates a set of new users.
func (s *Server) BatchCreateUser(context.Context, *pb.BatchCreateUserRequest) (*ktpb.User, error) {
	panic("unimplemented")
}

// BatchUpdateUser updates a set of users.
func (s *Server) BatchUpdateUser(context.Context, *pb.BatchUpdateUserRequest) (*ktpb.User, error) {
	panic("unimplemented")
}
