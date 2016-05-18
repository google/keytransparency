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

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/authentication"
	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/mutator"
	"github.com/google/e2e-key-server/queue"
	"github.com/google/e2e-key-server/tree"
	"github.com/google/e2e-key-server/vrf"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
)

var requiredScopes = []string{"https://www.googleapis.com/auth/userinfo.email"}

// Server holds internal state for the key server.
type Server struct {
	committer commitments.Committer
	queue     queue.Queuer
	auth      authentication.Authenticator
	tree      tree.SparseHist
	appender  appender.Appender
	vrf       vrf.PrivateKey
	mutator   mutator.Mutator
}

// Create creates a new instance of the key server.
func New(committer commitments.Committer, queue queue.Queuer, tree tree.SparseHist, appender appender.Appender, vrf vrf.PrivateKey, mutator mutator.Mutator) *Server {
	return &Server{
		committer: committer,
		queue:     queue,
		auth:      authentication.New(),
		tree:      tree,
		appender:  appender,
		vrf:       vrf,
		mutator:   mutator,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
	vrf, proof := s.vrf.Evaluate([]byte(in.UserId))
	index := s.vrf.Index(vrf)

	if in.EpochEnd == 0 {
		in.EpochEnd = s.appender.Latest(ctx)
	}
	data, err := s.appender.GetByIndex(ctx, in.EpochEnd)
	if err != nil {
		return nil, err
	}
	seh := new(ctmap.SignedEpochHead)
	err = proto.Unmarshal(data, seh)
	if err != nil {
		return nil, err
	}

	neighbors, err := s.tree.NeighborsAt(ctx, index[:], in.EpochEnd)
	if err != nil {
		return nil, err
	}

	// Retrieve the leaf if this is not a proof of absence.
	leaf, err := s.tree.ReadLeafAt(ctx, index[:], in.EpochEnd)
	if err != nil {
		return nil, err
	}
	commitment := &commitments.Commitment{}
	if leaf != nil {
		entry := pb.Entry{}
		if err := proto.Unmarshal(leaf, &entry); err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
		}

		commitment, err = s.committer.ReadCommitment(ctx, entry.Commitment)
		if err != nil {
			return nil, err
		}
		if commitment == nil {
			return nil, grpc.Errorf(codes.NotFound, "Commitment %v not found", entry.Commitment)
		}
	}

	return &pb.GetEntryResponse{
		Vrf:           vrf,
		VrfProof:      proof,
		CommitmentKey: commitment.Key,
		Profile:       commitment.Data,
		LeafProof: &ctmap.GetLeafResponse{
			LeafData:  leaf,
			Neighbors: neighbors,
		},
		// TODO Append only proof from EpochStart
		ConsistencyProof: nil,
		Sth:              &ctmap.GetSTHResponse{seh},
	}, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	return nil, grpc.Errorf(codes.Unimplemented, "Unimplemented")
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *pb.UpdateEntryRequest) (*pb.UpdateEntryResponse, error) {
	// Validate proper authentication.
	if !s.auth.ValidateCreds(ctx, in.UserId, requiredScopes) {
		return nil, grpc.Errorf(codes.PermissionDenied, "Permission Denied")
	}
	// Verify:
	// - Index to Key equality in SignedKV.
	// - Correct profile commitment.
	// - Correct key formats.
	if err := validateUpdateEntryRequest(in, s.vrf); err != nil {
		return nil, err
	}

	vrf, _ := s.vrf.Evaluate([]byte(in.UserId))
	index := s.vrf.Index(vrf)

	// Unmarshal entry.
	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(in.GetUpdate().KeyValue, kv); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return nil, err
	}
	entry := new(pb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		log.Printf("Error unmarshaling entry: %v", err)
		return nil, err
	}

	// Save the commitment.
	if err := s.committer.WriteCommitment(ctx, entry.Commitment, in.CommitmentKey, in.Profile); err != nil {
		return nil, err
	}

	// Query for the current epoch.
	req := &pb.GetEntryRequest{
		UserId:     in.UserId,
		EpochStart: in.EpochStart,
	}
	resp, err := s.GetEntry(ctx, req)
	if err != nil {
		return nil, err
	}

	// Catch errors early. Perform mutation verification.
	// Read at the current value.  Assert the following:
	// - TODO: Correct signatures from previous epoch.
	// - TODO: Corerct signatures internal to the update.
	// - TODO: Hash of current data matches the expectation in the mutation.
	// - Advanced update count.

	m, err := proto.Marshal(in.GetUpdate())
	if err != nil {
		return nil, err
	}

	oldEntry := new(pb.Entry)
	if err := proto.Unmarshal(resp.LeafProof.LeafData, oldEntry); err != nil {
		log.Printf("Error unmarshaling oldEntry: %v", err)
		return nil, err
	}
	if err := s.mutator.CheckMutation(resp.LeafProof.LeafData, m); err == mutator.ErrReplay {
		// This request has already been recieved and processed.
		log.Printf("Discarding request due to replay")
		return &pb.UpdateEntryResponse{resp}, nil
	} else if err != nil {
		return nil, err
	}

	if err := s.queue.Enqueue(index[:], m); err != nil {
		return nil, err
	}
	return &pb.UpdateEntryResponse{resp}, err
}
