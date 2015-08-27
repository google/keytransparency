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
	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Server holds internal state for the key server.
type Server struct {
	store  storage.Storage
	auth auth.Authenticator
	tree *merkle.Tree
}

// Create creates a new instance of the key server with an arbitrary datastore.
func New(storage storage.Storage, tree *merkle.Tree) *Server {
	srv := &Server{
		store:  storage,
		auth: auth.New(),
		tree: tree,
	}
	return srv
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *v2pb.GetEntryRequest) (*v2pb.GetEntryResponse, error) {
	vuf, index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while calculating VUF of user's ID")
	}

	// Get the commitment timestamp corresponding to the user's profile in
	// the given, or latest, epoch.
	epoch := in.Epoch
	if epoch == 0 {
		epoch = merkle.GetCurrentEpoch()
	}
	commitmentTS, err := s.tree.GetLeafCommitmentTimestamp(epoch, index)
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			// Return an empty proof.
			return proofOfAbsence(vuf), nil
		}
		return nil, err
	}

	entryStorage, err := s.store.Read(ctx, commitmentTS)
	if err != nil {
		if grpc.Code(err) == codes.NotFound {
			// Return an empty proof.
			return proofOfAbsence(vuf), nil
		}
		return nil, err
	}

	seu := new(v2pb.SignedEntryUpdate)
	entry := new(v2pb.Entry)

	if err := proto.Unmarshal(entryStorage.SignedEntryUpdate, seu); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal signed_entry_update")
	}
	if err := proto.Unmarshal(seu.Entry, entry); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal entry")
	}

	result := &v2pb.GetEntryResponse{
		Entry:          entry,
		Profile:        entryStorage.Profile,
		ProfileNonce: entryStorage.ProfileNonce,
		//TODO(cesarghali): add Seh
		IndexSignature: vuf,
	}
	return result, nil
}

func proofOfAbsence(vuf []byte) *v2pb.GetEntryResponse {
	return &v2pb.GetEntryResponse{
		IndexSignature: vuf,
	}
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *v2pb.ListEntryHistoryRequest) (*v2pb.ListEntryHistoryResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *v2pb.UpdateEntryRequest) (*v2pb.UpdateEntryResponse, error) {
	if err := s.validateUpdateEntryRequest(ctx, in); err != nil {
		return nil, err
	}

	e := &corepb.EntryStorage{
		// CommitmentTimestamp is set by storage.
		SignedEntryUpdate: in.GetUpdate().SignedEntryUpdate,
		Profile:     in.GetUpdate().Profile,
		ProfileNonce: in.GetUpdate().ProfileNonce,
		// TODO(cesarghali): set Domain.
	}

	// If entry does not exist, insert it, otherwise update.
	if err := s.store.Write(ctx, e); err != nil {
		return nil, err
	}

	return &v2pb.UpdateEntryResponse{}, nil
	// TODO: return proof if the entry has been added in an epoch alredy.
}

// List the Signed Epoch Heads, from epoch to epoch.
func (s *Server) ListSEH(ctx context.Context, in *v2pb.ListSEHRequest) (*v2pb.ListSEHResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// List the SignedEntryUpdates by update number.
func (s *Server) ListUpdate(ctx context.Context, in *v2pb.ListUpdateRequest) (*v2pb.ListUpdateResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// ListSteps combines SEH and SignedEntryUpdates into single list.
func (s *Server) ListSteps(ctx context.Context, in *v2pb.ListStepsRequest) (*v2pb.ListStepsResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}
