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
	"encoding/hex"

	"github.com/golang/protobuf/proto"
	"github.com/google/e2e-key-server/auth"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	proto3 "google/protobuf"
)

// Server holds internal state for the key server.
type Server struct {
	store storage.Storage
	auth  auth.Authenticator
	tree  *merkle.Tree
}

// Create creates a new instance of the key server with an arbitrary datastore.
func New(storage storage.Storage, tree *merkle.Tree) *Server {
	srv := &Server{
		store: storage,
		auth:  auth.New(),
		tree:  tree,
	}
	return srv
}

// GetUser returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetUser also supports querying past values by setting the epoch field.
func (s *Server) GetUser(ctx context.Context, in *v2pb.GetUserRequest) (*v2pb.EntryProfileAndProof, error) {
	_, index, err := s.Vuf(in.UserId)
	if err != nil {
		return nil, err
	}

	vuf, err := hex.DecodeString(index)
	if err != nil {
		return nil, err
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

	result := &v2pb.EntryProfileAndProof{
		Entry:        entry,
		Profile:      entryStorage.Profile,
		ProfileNonce: entryStorage.ProfileNonce,
		//TODO(cesarghali): add Seh
		IndexSignature: &v2pb.UVF{vuf},
	}
	return result, nil
}

func proofOfAbsence(vuf []byte) *v2pb.EntryProfileAndProof {
	return &v2pb.EntryProfileAndProof{
		IndexSignature: &v2pb.UVF{vuf},
	}
}

// ListUserHistory returns a list of UserProofs covering a period of time.
func (s *Server) ListUserHistory(ctx context.Context, in *v2pb.ListUserHistoryRequest) (*v2pb.ListUserHistoryResponse, error) {
	// Ensure that PageSize is not equal to 0.
	if in.PageSize == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "Page size cannot be 0")
	}

	historyResponse := new(v2pb.ListUserHistoryResponse)

	// Read current epoch and build the user history up to it. If the epoch
	// advances while building the history, future epochs will not be
	// included.
	nextEpoch, endEpoch, err := s.getNextAndEndEpoch(in.StartEpoch, merkle.GetCurrentEpoch(), in.PageSize)
	if err != nil {
		return nil, err
	}
	historyResponse.NextEpoch = nextEpoch

	// Get EntryProfileAndProof in epoch = [startEpoch, endEpoch].
	historyResponse.Values = make([]*v2pb.EntryProfileAndProof, endEpoch-in.StartEpoch+1)
	for i, _ := range historyResponse.Values {
		result, err := s.GetUser(ctx, &v2pb.GetUserRequest{
			// Use in.StartEpoch to shift the index i to the correct
			// epoch number.
			Epoch:  uint64(i) + in.StartEpoch,
			UserId: in.UserId,
		})
		if err != nil {
			return nil, err
		}
		historyResponse.Values[i] = result
	}

	return historyResponse, nil
}

// UpdateUser updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateUser(ctx context.Context, in *v2pb.UpdateUserRequest) (*proto3.Empty, error) {
	if err := s.validateUpdateUserRequest(ctx, in); err != nil {
		return nil, err
	}

	e := &corepb.EntryStorage{
		// CommitmentTimestamp is set by storage.
		SignedEntryUpdate: in.GetUpdate().SignedEntryUpdate,
		Profile:           in.GetUpdate().Profile,
		ProfileNonce:      in.GetUpdate().ProfileNonce,
		// TODO(cesarghali): set Domain.
	}

	// If entry does not exist, insert it, otherwise update.
	if err := s.store.Write(ctx, e); err != nil {
		return nil, err
	}

	return &proto3.Empty{}, nil
}

// List the Signed Epoch Heads, from epoch to epoch.
func (s *Server) ListSEH(ctx context.Context, in *v2pb.ListSEHRequest) (*v2pb.ListSEHResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// List the SignedEntryUpdates by update number.
func (s *Server) ListUpdate(ctx context.Context, in *v2pb.ListUpdateRequest) (*v2pb.ListUpdateResponse, error) {
	// Ensure that PageSize is not equal to 0.
	if in.PageSize == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument, "Page size cannot be 0")
	}

	updateResponse := new(v2pb.ListUpdateResponse)

	// Read current commitment timestamp and build the updates list up to
	// it. If the timestamp advances while building the history, future
	// timestamps will not be included.
	currentCommitmentTS := storage.GetCurrentCommitmentTimestamp()
	if in.StartCommitmentTimestamp > currentCommitmentTS {
		return nil, grpc.Errorf(codes.InvalidArgument, "Start commitment timestamp does not exist")
	}

	// Get SignedEntryUpdates in timestamp = [startCommitmentTS,
	// endCommitmentTS].
	res, err := s.store.ReadRange(ctx, in.StartCommitmentTimestamp, in.PageSize)
	if err != nil {
		return nil, err
	}
	for _, entryStorage := range res {
		updateResponse.Updates = append(updateResponse.Updates, entryStorage.SignedEntryUpdate)
	}

	return updateResponse, nil
}

// ListSteps combines SEH and SignedEntryUpdates into single list.
func (s *Server) ListSteps(ctx context.Context, in *v2pb.ListStepsRequest) (*v2pb.ListStepsResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// getNextAndEndEpoch returns the next and end epochs based on start and current
// epochs.
func (s *Server) getNextAndEndEpoch(start uint64, current uint64, pageSize int32) (uint64, uint64, error) {
	if start > current {
		return 0, 0, grpc.Errorf(codes.InvalidArgument, "Start interval does not exist")
	}

	// By default next is zero and end is equal to current. Zero next means
	// all requested entries are returned.
	next := uint64(0)
	end := current
	// pageSize equals to 0 means no limit on number of entries. if it's not
	// and the calculated next does not exceed or equal to current, set both
	// end and next to their calculated values.
	if current > start+uint64(pageSize)-1 {
		end = start + uint64(pageSize) - 1
		next = end + 1
	}

	return next, end, nil
}
