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
	"bytes"

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/builder"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Server holds internal state for the key server.
type Server struct {
	store   storage.ConsistentStorage
	auth    auth.Authenticator
	builder *builder.Builder
}

// Create creates a new instance of the key server with an arbitrary datastore.
func New(storage storage.ConsistentStorage, builder *builder.Builder) *Server {
	return &Server{
		store:   storage,
		auth:    auth.New(),
		builder: builder,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *v2pb.GetEntryRequest) (*v2pb.GetEntryResponse, error) {
	index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Error while calculating VUF of user's ID")
	}

	// result contains the returned GetEntryResponse.
	result := &v2pb.GetEntryResponse{
		Index: index,
		// TODO(cesarghali): Fill IndexProof.
	}

	// Get signed epoch heads.
	seh, err := s.builder.GetSignedEpochHeads(ctx, in.Epoch)
	if err != nil {
		return nil, err
	}
	result.SignedEpochHeads = seh

	// Get merkle tree neighbors, and commitment timestamp.
	neighbors, commitmentTS, err := s.builder.AuditPath(in.Epoch, index)
	result.MerkleTreeNeighbors = neighbors

	if err != nil {
		return nil, err
	}

	// If commitmentTS is equal to 0, then an empty branch was found, and
	// no Entry should be returned.
	if commitmentTS != 0 {
		// Read EntryStorage from the data store.
		entryStorage, err := s.store.ReadUpdate(ctx, commitmentTS)
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, "Error while reading the requested profile in the data store")
		}

		// Unmarshal entry.
		entry := new(v2pb.Entry)
		if err := proto.Unmarshal(entryStorage.GetSignedEntryUpdate().NewEntry, entry); err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
		}

		result.Entry = entry

		// If entryStorage.SignedEntryUpdate.NewEntry have an
		// exact index as the requested one, fill out the
		// corresponding profile and its commitment.
		if bytes.Equal(entry.Index, index) {
			result.Profile = entryStorage.Profile
			result.CommitmentKey = entryStorage.CommitmentKey
		}
	}

	return result, nil
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
		SignedEntryUpdate: in.GetSignedEntryUpdate(),
		Profile:           in.Profile,
		CommitmentKey:     in.CommitmentKey,
		// TODO(cesarghali): set Domain.
	}

	// If entry does not exist, insert it, otherwise update.
	if err := s.store.WriteUpdate(ctx, e); err != nil {
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
