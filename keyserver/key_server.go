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
	"log"
	"math"

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/builder"
	"github.com/google/e2e-key-server/db"
	"github.com/google/e2e-key-server/tree"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	corepb "github.com/google/e2e-key-server/proto/security_e2ekeys_core"
	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

// Server holds internal state for the key server.
type Server struct {
	committer db.Committer
	queue     db.Queuer
	store     db.Distributed
	auth      auth.Authenticator
	tree      tree.Sparse
	builder   *builder.Builder
	appender  appender.Appender
}

// Create creates a new instance of the key server with an arbitrary datastore.
func New(committer db.Committer, queue db.Queuer, storage db.Distributed, tree tree.Sparse, builder *builder.Builder, appender appender.Appender) *Server {
	return &Server{
		committer: committer,
		queue:     queue,
		store:     storage,
		auth:      auth.New(),
		builder:   builder,
		tree:      tree,
		appender:  appender,
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

	// Get an append-only proof for the signed tree head.
	e := in.Epoch
	if in.Epoch == math.MaxInt64 {
		e = s.appender.Latest(ctx)
	}
	data, err := s.appender.GetByIndex(ctx, e)
	if err != nil {
		return nil, err
	}
	seh := ctmap.SignedEpochHead{}
	err = proto.Unmarshal(data, &seh)
	if err != nil {
		return nil, err
	}

	// result contains the returned GetEntryResponse.
	result := &v2pb.GetEntryResponse{
		Index:            index,
		SignedEpochHeads: []*ctmap.SignedEpochHead{&seh},
		// TODO(cesarghali): Fill IndexProof.
	}

	// Retrieve the leaf if this is not a proof of absence.
	leaf, err := s.tree.ReadLeaf(ctx, index)
	if err == nil {
		result.Entry = new(ctmap.Entry)
		if err := proto.Unmarshal(leaf, result.Entry); err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
		}

		// If entryStorage.SignedEntryUpdate.NewEntry have an
		// exact index as the requested one, fill out the
		// corresponding profile and its commitment.
		if bytes.Equal(result.Entry.Index, index) {
			commitment, err := s.committer.ReadCommitment(ctx, result.Entry.ProfileCommitment)
			if err != nil {
				return nil, err
			}
			result.Profile = commitment.Data
			result.CommitmentKey = commitment.Key

		}
	}

	neighbors, err := s.tree.Neighbors(ctx, index)
	log.Printf("Neighbors(%v)=%v,%v", index, neighbors, err)
	// TODO: return historical values for epoch.
	result.MerkleTreeNeighbors = neighbors
	if err != nil {
		return nil, err
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
	// ---
	index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}
	// TODO: what should the mutation be?
	// Option A: an update to the commitment
	m, err := proto.Marshal(in.GetSignedEntryUpdate())
	if err != nil {
		return nil, err
	}
	// Option B: an update to the particular key
	// Update the SignedDataTypes to include the particular keys etc.

	// Unmarshal entry.
	entry := new(ctmap.Entry)
	if err := proto.Unmarshal(in.GetSignedEntryUpdate().NewEntry, entry); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
	}

	if err := s.committer.WriteCommitment(ctx, entry.ProfileCommitment, in.CommitmentKey, in.Profile); err != nil {
		return nil, err
	}

	if err := s.queue.QueueMutation(ctx, index, m); err != nil {
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
