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
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	internalpb "github.com/google/e2e-key-server/proto/internal"
	keyspb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
	proto3 "google/protobuf"
)

// Server holds internal state for the key server.
type Server struct {
	s storage.Storage
	a auth.Authenticator
	t *merkle.Tree
}

// Create creates a new instance of the key server with an arbitrary datastore.
func New(storage storage.Storage, tree *merkle.Tree) *Server {
	srv := &Server{
		s: storage,
		a: auth.New(),
		t: tree,
	}
	return srv
}

// GetUser returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetUser also supports querying past values by setting the epoch field.
func (s *Server) GetUser(ctx context.Context, in *keyspb.GetUserRequest) (*keyspb.EntryProfileAndProof, error) {
	_, index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	e, err := s.s.Read(ctx, index)
	if err != nil {
		return nil, err
	}

	// This key server doesn't employ a merkle tree yet. This is why most of
	// fields in EntryProfileAndProof do not exist.
	// TODO(cesarghali): integrate merkle tree.
	result := &keyspb.EntryProfileAndProof{
		Profile: e.Profile,
	}
	return result, nil
}

// ListUserHistory returns a list of UserProofs covering a period of time.
func (s *Server) ListUserHistory(ctx context.Context, in *keyspb.ListUserHistoryRequest) (*keyspb.ListUserHistoryResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// UpdateUser updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateUser(ctx context.Context, in *keyspb.UpdateUserRequest) (*proto3.Empty, error) {
	if err := s.validateUpdateUserRequest(ctx, in); err != nil {
		return nil, err
	}

	_, index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	e := &internalpb.EntryStorage{
		// Epoch is the epoch at which this update should be inserted
		// into the merkle tree.
		// TODO(cesarghali): for now epoch = current + 1. This might
		//                   change in the future.
		Epoch: uint64(merkle.GetCurrentEpoch()),
		// TODO(cesarghali): sequence should be set properly.
		Sequence:    0,
		EntryUpdate: in.GetUpdate().SignedUpdate,
		Profile:     in.GetUpdate().Profile,
		// TODO(cesarghali): set Domain.
	}

	// If entry does not exist, insert it, otherwise update.
	if err = s.s.Write(ctx, e, index); err != nil {
		return nil, err
	}

	return &proto3.Empty{}, nil
}

// List the Signed Epoch Heads, from epoch to epoch.
func (s *Server) ListSEH(ctx context.Context, in *keyspb.ListSEHRequest) (*keyspb.ListSEHResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// List the EntryUpdates by update number.
func (s *Server) ListUpdate(ctx context.Context, in *keyspb.ListUpdateRequest) (*keyspb.ListUpdateResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// ListSteps combines SEH and EntryUpdates into single list.
func (s *Server) ListSteps(ctx context.Context, in *keyspb.ListStepsRequest) (*keyspb.ListStepsResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}
