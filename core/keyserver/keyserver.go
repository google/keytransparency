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
	"log"

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

const (
	// Each page contains pageSize profiles. Each profile contains multiple
	// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
	// size 16 will contain about 8KB of data.
	defaultPageSize = 16
	// Maximum allowed requested page size to prevent DOS.
	maxPageSize = 16
)

// Server holds internal state for the key server.
type Server struct {
	mapID     int64
	tmap      trillian.TrillianMapClient
	logID     int64
	committer commitments.Committer
	auth      authentication.Authenticator
	vrf       vrf.PrivateKey
	mutator   mutator.Mutator
	factory   transaction.Factory
	mutations mutator.Mutation
}

// New creates a new instance of the key server.
func New(logID int64,
	mapID int64,
	tmap trillian.TrillianMapClient,
	committer commitments.Committer,
	vrf vrf.PrivateKey,
	mutator mutator.Mutator,
	auth authentication.Authenticator,
	factory transaction.Factory,
	mutations mutator.Mutation) *Server {
	return &Server{
		mapID:     mapID,
		tmap:      tmap,
		logID:     logID,
		committer: committer,
		vrf:       vrf,
		mutator:   mutator,
		auth:      auth,
		factory:   factory,
		mutations: mutations,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *tpb.GetEntryRequest) (*tpb.GetEntryResponse, error) {
	resp, err := s.getEntry(ctx, in.UserId, -1)
	if err != nil {
		log.Printf("getEntry failed: %v", err)
		return nil, grpc.Errorf(codes.Internal, "GetEntry failed")
	}
	return resp, nil
}

func (s *Server) getEntry(ctx context.Context, userID string, epoch int64) (*tpb.GetEntryResponse, error) {
	vrf, proof := s.vrf.Evaluate([]byte(userID))
	index := s.vrf.Index(vrf)

	getResp, err := s.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId:    s.mapID,
		Index:    [][]byte{index[:]},
		Revision: epoch,
	})
	if err != nil {
		log.Printf("GetLeaves(): %v", err)
		return nil, grpc.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.MapLeafInclusion), 1; got != want {
		log.Printf("GetLeaves() len: %v, want %v", got, want)
		return nil, grpc.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	neighbors := getResp.MapLeafInclusion[0].Inclusion
	leaf := getResp.MapLeafInclusion[0].Leaf.LeafValue

	var committed *tpb.Committed
	if leaf != nil {
		entry := tpb.Entry{}
		if err := proto.Unmarshal(leaf, &entry); err != nil {
			log.Printf("Error unmarshaling entry: %v", err)
			return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
		}

		committed, err = s.committer.Read(ctx, entry.Commitment)
		if err != nil {
			log.Printf("Cannot read committed value: %v", err)
			return nil, grpc.Errorf(codes.Internal, "Cannot read committed value")
		}
		if committed == nil {
			return nil, grpc.Errorf(codes.NotFound, "Commitment %v not found", entry.Commitment)
		}
	}

	return &tpb.GetEntryResponse{
		Vrf:       vrf,
		VrfProof:  proof,
		Committed: committed,
		LeafProof: &trillian.MapLeafInclusion{
			Inclusion: neighbors,
			Leaf: &trillian.MapLeaf{
				LeafValue: leaf,
			},
		},
		Smr: getResp.GetMapRoot(),
	}, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *tpb.ListEntryHistoryRequest) (*tpb.ListEntryHistoryResponse, error) {
	// Get current epoch.
	resp, err := s.getEntry(ctx, in.UserId, -1)
	if err != nil {
		log.Printf("GetEntry(%v): %v", in.UserId, err)
		return nil, grpc.Errorf(codes.InvalidArgument, "getEntry failed")
	}

	currentEpoch := resp.GetSmr().MapRevision
	if err := validateListEntryHistoryRequest(in, currentEpoch); err != nil {
		log.Printf("validateListEntryHistoryRequest(%v, %v): %v", in, currentEpoch, err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// Get all GetEntryResponse for all epochs in the range [start, start +
	// in.PageSize].
	responses := make([]*tpb.GetEntryResponse, in.PageSize)
	for i := range responses {
		resp, err := s.getEntry(ctx, in.UserId, in.Start+int64(i))
		if err != nil {
			log.Printf("getEntry failed for epoch %v: %v", in.Start+int64(i), err)
			return nil, grpc.Errorf(codes.Internal, "GetEntry failed")
		}
		responses[i] = resp
	}

	nextStart := in.Start + int64(in.PageSize)
	if nextStart > currentEpoch {
		nextStart = 0
	}

	return &tpb.ListEntryHistoryResponse{
		Values:    responses,
		NextStart: nextStart,
	}, nil
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *tpb.UpdateEntryRequest) (*tpb.UpdateEntryResponse, error) {
	// Validate proper authentication.
	if err := s.auth.ValidateCreds(ctx, in.UserId); err != nil {
		log.Printf("Auth failed: %v", err)
		return nil, grpc.Errorf(codes.PermissionDenied, "Permission denied")
	}
	// Verify:
	// - Index to Key equality in SignedKV.
	// - Correct profile commitment.
	// - Correct key formats.
	if err := validateUpdateEntryRequest(in, s.vrf); err != nil {
		log.Printf("Invalid UpdateEntryRequest: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	if err := s.saveCommitment(ctx, in.GetEntryUpdate().GetUpdate().GetKeyValue(), in.GetEntryUpdate().Committed); err != nil {
		return nil, err
	}

	// Query for the current epoch.
	req := &tpb.GetEntryRequest{
		UserId: in.UserId,
		//EpochStart: in.GetEntryUpdate().EpochStart,
	}
	resp, err := s.GetEntry(ctx, req)
	if err != nil {
		log.Printf("GetEntry failed: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Read failed")
	}

	// Catch errors early. Perform mutation verification.
	// Read at the current value.  Assert the following:
	// - Correct signatures from previous epoch.
	// - Correct signatures internal to the update.
	// - Hash of current data matches the expectation in the mutation.

	m, err := proto.Marshal(in.GetEntryUpdate().GetUpdate())
	if err != nil {
		log.Printf("Marshal error of Update: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Marshaling error")
	}

	// The very first mutation will have resp.LeafProof.LeafData=nil.
	if err := s.mutator.CheckMutation(resp.LeafProof.Leaf.LeafValue, m); err == mutator.ErrReplay {
		log.Printf("Discarding request due to replay")
		// Return the response. The client should handle the replay case
		// by comparing the returned response with the request. Check
		// Retry() in client/client.go.
		return &tpb.UpdateEntryResponse{Proof: resp}, nil
	} else if err != nil {
		log.Printf("Invalid mutation: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid mutation")
	}

	// Save mutation to the database.
	txn, err := s.factory.NewTxn(ctx)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot create transaction")
	}
	if _, err := s.mutations.Write(txn, in.GetEntryUpdate().GetUpdate()); err != nil {
		log.Printf("mutations.Write failed: %v", err)
		if err := txn.Rollback(); err != nil {
			log.Printf("Cannot rollback the transaction: %v", err)
		}
		return nil, grpc.Errorf(codes.Internal, "Mutation write error")
	}
	if err := txn.Commit(); err != nil {
		log.Printf("Cannot commit transaction: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Cannot commit transaction")
	}
	return &tpb.UpdateEntryResponse{Proof: resp}, nil
}

func (s *Server) saveCommitment(ctx context.Context, kv *tpb.KeyValue, committed *tpb.Committed) error {
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		log.Printf("Error unmarshaling entry: %v", err)
		return grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// Write the commitment.
	if err := s.committer.Write(ctx, entry.Commitment, committed); err != nil {
		log.Printf("committer.Write failed: %v", err)
		return grpc.Errorf(codes.Internal, "Write failed")
	}
	return nil
}
