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

// Package keyserver implements a transparent key server for End to End.
package keyserver

import (
	"bytes"
	"math"

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/db"
	"github.com/google/e2e-key-server/db/commitments"
	"github.com/google/e2e-key-server/tree"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
)

// Server holds internal state for the key server.
type Server struct {
	committer commitments.Committer
	queue     db.Queuer
	auth      auth.Authenticator
	tree      tree.SparseHist
	appender  appender.Appender
}

// Create creates a new instance of the key server.
func New(committer commitments.Committer, queue db.Queuer, tree tree.SparseHist, appender appender.Appender) *Server {
	return &Server{
		committer: committer,
		queue:     queue,
		auth:      auth.New(),
		tree:      tree,
		appender:  appender,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
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

	neighbors, err := s.tree.NeighborsAt(ctx, index, e)
	if err != nil {
		return nil, err
	}

	// result contains the returned GetEntryResponse.
	result := &pb.GetEntryResponse{
		Index:            index,
		SignedEpochHeads: []*ctmap.SignedEpochHead{&seh},
		// TODO(cesarghali): Fill IndexProof.
		MerkleTreeNeighbors: neighbors,
	}

	// Retrieve the leaf if this is not a proof of absence.
	leaf, err := s.tree.ReadLeafAt(ctx, index, e)
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

	return result, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *pb.UpdateEntryRequest) (*pb.UpdateEntryResponse, error) {
	if err := s.validateUpdateEntryRequest(ctx, in); err != nil {
		return nil, err
	}

	index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}
	// The mutation is an update to the commitment.
	m, err := proto.Marshal(in.GetSignedEntryUpdate())
	if err != nil {
		return nil, err
	}

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

	return &pb.UpdateEntryResponse{}, nil
	// TODO: return proof if the entry has been added in an epoch alredy.
}

// List the Signed Epoch Heads, from epoch to epoch.
func (s *Server) ListSEH(ctx context.Context, in *pb.ListSEHRequest) (*pb.ListSEHResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// List the SignedEntryUpdates by update number.
func (s *Server) ListUpdate(ctx context.Context, in *pb.ListUpdateRequest) (*pb.ListUpdateResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// ListSteps combines SEH and SignedEntryUpdates into single list.
func (s *Server) ListSteps(ctx context.Context, in *pb.ListStepsRequest) (*pb.ListStepsResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}
