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

// This iteration of the key server, stores keys directly in the verifiable map

import (
	"bytes"
	"math"

	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/db/commitments"

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
	auth      auth.Authenticator

	cli *ctmap.VerifiableMapClient
}

// Create creates a new instance of the key server.
func New(cli *ctmap.Client, committer commitments.Committer, queue queue.Queuer, tree tree.SparseHist, appender appender.Appender) *Server {
	return &Server{
		committer: committer,
		auth:      auth.New(),
		cli:       cli,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
	index, err := s.Vuf(in.UserId)
	if err != nil {
		return err
	}

	// Get the proof of inclusion and the leaf data.
	resp, err := s.cli.Get(index, in.epoch)

	// Use the leaf data to lookup the commitment.
	if resp != nil {
		commitment, err := s.committer.ReadCommitment(ctx, resp.Entry.ProfileCommitment)
		if err != nil {
			return nil, err
		}
	}

	return &pb.GetEntryResponse{
		Index:               index,
		IndexProof:          nil, // TODO(cesarghali): Fill IndexProof.
		MerkleTreeNeighbors: neighbors,

		Profile:       commitment.Data,
		CommitmentKey: commitment.Key,
	}, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	// a future version of this function would return a merkle tree full of
	// history.
	items := min(in.end-in.start, paging)
	end := in.start + items
	resp := make([]resp, items)
	// query the database iterativly
	for i, _ := range resp {
		epoch := in.start + i
		resp[i] = s.cli.Get(index, epoch)
	}
	return resp, nil
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *pb.UpdateEntryRequest) (*pb.UpdateEntryResponse, error) {
	// TODO: verify that the data the mutation references is current.
	// Do this in the mutation validator.
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

	if err := s.queue.Enqueue(index, m); err != nil {
		return nil, err
	}

	return &pb.UpdateEntryResponse{}, nil
	// TODO: return proof if the entry has been added in an epoch alredy.
}
