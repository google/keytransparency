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

	"github.com/google/key-transparency/appender"
	"github.com/google/key-transparency/authentication"
	"github.com/google/key-transparency/commitments"
	"github.com/google/key-transparency/mutator"
	"github.com/google/key-transparency/queue"
	"github.com/google/key-transparency/tree"
	"github.com/google/key-transparency/vrf"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	ctmap "github.com/google/key-transparency/proto/ctmap"
	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

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

// New creates a new instance of the key server.
func New(committer commitments.Committer, queue queue.Queuer, tree tree.SparseHist, appender appender.Appender, vrf vrf.PrivateKey, mutator mutator.Mutator, auth authentication.Authenticator) *Server {
	return &Server{
		committer: committer,
		queue:     queue,
		auth:      auth,
		tree:      tree,
		appender:  appender,
		vrf:       vrf,
		mutator:   mutator,
	}
}

// GetSMH returns the current Signed Map Head (SMH).
func (s *Server) GetSMH(ctx context.Context, epoch int64) (int64, *ctmap.SignedMapHead, []byte, error) {
	var sct []byte
	smh := new(ctmap.SignedMapHead)
	thisEpoch := epoch
	var err error
	if epoch == 0 {
		thisEpoch, sct, err = s.appender.Latest(ctx, smh)
	} else {
		sct, err = s.appender.Epoch(ctx, epoch, smh)
	}
	if err != nil {
		return 0, nil, nil, err
	}
	return thisEpoch, smh, sct, nil
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
	vrf, proof := s.vrf.Evaluate([]byte(in.UserId))
	index := s.vrf.Index(vrf)

	epoch, smh, sct, err := s.GetSMH(ctx, in.EpochEnd)
	if err != nil {
		return nil, err
	}

	neighbors, err := s.tree.NeighborsAt(ctx, index[:], epoch)
	if err != nil {
		return nil, err
	}

	// Retrieve the leaf if this is not a proof of absence.
	leaf, err := s.tree.ReadLeafAt(ctx, index[:], epoch)
	if err != nil {
		return nil, err
	}
	var committed *pb.Committed
	if leaf != nil {
		entry := pb.Entry{}
		if err := proto.Unmarshal(leaf, &entry); err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot unmarshal entry")
		}

		committed, err = s.committer.Read(ctx, entry.Commitment)
		if err != nil {
			return nil, err
		}
		if committed == nil {
			return nil, grpc.Errorf(codes.NotFound, "Commitment %v not found", entry.Commitment)
		}
	}

	return &pb.GetEntryResponse{
		Vrf:       vrf,
		VrfProof:  proof,
		Committed: committed,
		// Leaf proof in sparse merkle tree.
		LeafProof: &ctmap.GetLeafResponse{
			LeafData:  leaf,
			Neighbors: neighbors,
		},
		Smh:    smh,
		SmhSct: sct,
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

	vrf, _ := s.vrf.Evaluate([]byte(in.UserId))
	index := s.vrf.Index(vrf)

	// Unmarshal entry.
	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(in.GetEntryUpdate().GetUpdate().KeyValue, kv); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}
	entry := new(pb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		log.Printf("Error unmarshaling entry: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// Save the commitment.
	if err := s.committer.Write(ctx, entry.Commitment, in.GetEntryUpdate().Committed); err != nil {
		log.Printf("committer.Write failed: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Write failed")
	}

	// Query for the current epoch.
	req := &pb.GetEntryRequest{
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
	// - TODO: Correct signatures from previous epoch.
	// - TODO: Correct signatures internal to the update.
	// - Hash of current data matches the expectation in the mutation.
	// - Advanced update count.

	m, err := proto.Marshal(in.GetEntryUpdate().GetUpdate())
	if err != nil {
		log.Printf("Marshal error of Update: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Marshaling error")
	}

	oldEntry := new(pb.Entry)
	if err := proto.Unmarshal(resp.LeafProof.LeafData, oldEntry); err != nil {
		log.Printf("Error unmarshaling oldEntry: %v", err)
		return nil, err
	}
	// The very first mutation will have resp.LeafProof.LeafData=nil.
	if err := s.mutator.CheckMutation(resp.LeafProof.LeafData, m); err == mutator.ErrReplay {
		log.Printf("Discarding request due to replay")
		// Return the response. The client should handle the replay case
		// by comparing the returned response with the request. Check
		// Retry() in client/client.go.
		return &pb.UpdateEntryResponse{Proof: resp}, nil
	} else if err != nil {
		log.Printf("Invalid mutation: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid mutation")
	}

	if err := s.queue.Enqueue(index[:], m); err != nil {
		log.Printf("Enqueue error: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Write error")
	}
	return &pb.UpdateEntryResponse{Proof: resp}, err
}
