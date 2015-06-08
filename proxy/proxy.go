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
// Package proxy converts v1 API requests into v2 API calls.
package proxy

import (
	"time"

	"github.com/google/e2e-key-server/keyserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
	proto3 "google/protobuf"
)

// Server holds internal state for the proxy server.
type Server struct {
	s *keyserver.Server
}

// New creates a new instance of the proxy server.
func New(svr *keyserver.Server) *Server {
	return &Server{svr}
}

// GetUser returns a user's keys.
func (s *Server) GetUser(ctx context.Context, in *v2pb.GetUserRequest) (*v2pb.User, error) {
	proof, err := s.s.GetUser(ctx, in)
	if err != nil {
		return nil, err
	}

	// Append promises
	var signedKeyPromises []*v2pb.SignedKey
	for _, promise := range proof.Promises {
		signedKeyPromises = append(signedKeyPromises, promise.SignedKeyTimestamp.SignedKey)
	}
	out := proof.User
	out.SignedKeys = append(proof.User.SignedKeys, signedKeyPromises...)
	return out, nil
}

// CreateKey inserts a new key into the database.
func (s *Server) CreateKey(ctx context.Context, in *v2pb.CreateKeyRequest) (*v2pb.SignedKey, error) {
	// Add timestamp
	if in.GetSignedKey().GetKey() == nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Missing SignedKey.")
	}
	in.GetSignedKey().GetKey().CreationTime = &proto3.Timestamp{Seconds: time.Now().Unix()}

	promise, err := s.s.CreateKey(ctx, in)
	if err != nil {
		return nil, err
	}
	out := promise.SignedKeyTimestamp.SignedKey
	return out, nil
}

// UpdateKey updates a device key.
func (s *Server) UpdateKey(ctx context.Context, in *v2pb.UpdateKeyRequest) (*v2pb.SignedKey, error) {
	promise, err := s.s.UpdateKey(ctx, in)
	if err != nil {
		return nil, err
	}
	out := promise.SignedKeyTimestamp.SignedKey
	return out, nil
}

// DeleteKey deletes a key. Returns NOT_FOUND if the key does not exist.
func (s *Server) DeleteKey(ctx context.Context, in *v2pb.DeleteKeyRequest) (*proto3.Empty, error) {
	return s.s.DeleteKey(ctx, in)
}
