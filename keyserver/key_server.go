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

// Package keyserver implements a transparent key server for End to End.
package keyserver

import (
	"log"
	"time"

	"github.com/google/key-server-transparency/auth"
	"github.com/google/key-server-transparency/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	keyspb "github.com/google/key-server-transparency/proto/v2"
	context "golang.org/x/net/context"
	proto3 "google/protobuf"
)

// Server holds internal state for the key server.
type Server struct {
	s storage.BasicStorage
	a auth.Authenticator
}

// Open creates a new instance of the key server and connects to the database.
func Open(ctx context.Context, logID []byte, universe string, environment string) *Server {
	storage := storage.CreateMem(ctx)
	if storage == nil {
		log.Fatalf("Failed connecting to storage.")
	}

	// TODO: Add authenticator
	return &Server{storage, auth.New()}
}

// Create creates a new instance of the key server with an arbitrary datastore.
func Create(storage storage.BasicStorage) *Server {
	return &Server{storage, auth.New()}
}

// GetUser returns a user's keys and proof that there is only one object for this
// user and that it is the same one being provided to everyone else.
// GetUser also supports querying past values by setting the epoch field.
func (s *Server) GetUser(ctx context.Context, in *keyspb.GetUserRequest) (*keyspb.UserProof, error) {
	_, vuf, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	signedKey, err := s.s.ReadKey(ctx, vuf)
	if err != nil {
		return nil, err
	}
	p := &keyspb.UserProof{
		User: &keyspb.User{
			SignedKeys: []*keyspb.SignedKey{
				signedKey,
			},
		},
	}
	return p, nil // no error
}

// ListUserHistory returns a list of UserProofs covering a period of time.
func (s *Server) ListUserHistory(ctx context.Context, in *keyspb.ListUserHistoryRequest) (*keyspb.ListUserHistoryResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// CreateKey promises to create a new key for a user on the next epoch.  Multiple new
// keys can be created each epoch. Clients must verify that each promise is
// in-fact in the tree on the next epoch.
func (s *Server) CreateKey(ctx context.Context, in *keyspb.CreateKeyRequest) (*keyspb.KeyPromise, error) {
	if err := s.validateCreateKeyRequest(ctx, in); err != nil {
		return nil, err
	}

	_, vuf, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	if err = s.s.InsertKey(ctx, in.GetSignedKey(), vuf); err != nil {
		return nil, err
	}

	out := &keyspb.KeyPromise{
		SignedKeyTimestamp: &keyspb.SignedKeyTimestamp{
			SignedKey: in.GetSignedKey(),
			CreationTime: &proto3.Timestamp{
				Seconds: time.Now().Unix(),
			},
			Vuf: vuf,
		},
	}
	return out, nil
}

// UpdateKey updates a device key.
func (s *Server) UpdateKey(ctx context.Context, in *keyspb.UpdateKeyRequest) ( *keyspb.KeyPromise, error) {
	if err := s.validateUpdateKeyRequest(ctx, in); err != nil {
		return nil, err
	}

	_, vuf, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	if err = s.s.UpdateKey(ctx, in.GetSignedKey(), vuf); err != nil {
		return nil, err
	}

	out := &keyspb.KeyPromise{
		SignedKeyTimestamp: &keyspb.SignedKeyTimestamp{
			SignedKey: in.GetSignedKey(),
			CreationTime: &proto3.Timestamp{
				Seconds: time.Now().Unix(),
			},
			Vuf: vuf,
		},
	}
	return out, nil
}

// DeleteKey deletes a key. Returns NOT_FOUND if the key does not exist.
func (s *Server) DeleteKey(ctx context.Context, in *keyspb.DeleteKeyRequest) (*proto3.Empty, error){
	if err := s.validateEmail(ctx, in.UserId); err != nil {
		return nil, err
	}
	_, vuf, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}
	return &proto3.Empty{}, s.s.DeleteKey(ctx, vuf)
}
