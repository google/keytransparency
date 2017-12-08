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

// Package mutationserver implements a service that provides batches and
// streams of mutations to monitors for verification.
package mutationserver

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/keytransparency/core/adminstorage"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"

	"github.com/golang/glog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	tpb "github.com/google/trillian"
)

// Server holds internal state for the monitor server core functionality.
type Server struct {
	admin     adminstorage.Storage
	tlog      tpb.TrillianLogClient
	tmap      tpb.TrillianMapClient
	mutations mutator.MutationStorage
	factory   transaction.Factory
}

// New creates a new instance of the monitor server.
func New(admin adminstorage.Storage,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	mutations mutator.MutationStorage, factory transaction.Factory) *Server {
	return &Server{
		admin:     admin,
		tlog:      tlog,
		tmap:      tmap,
		mutations: mutations,
		factory:   factory,
	}
}

// GetMutations returns a list of mutations paged by epoch number.
func (s *Server) GetMutations(ctx context.Context, in *pb.GetMutationsRequest) (*pb.GetMutationsResponse, error) {
	if err := validateGetMutationsRequest(in); err != nil {
		glog.Errorf("validateGetMutationsRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}

	// Lookup log and map info.
	domain, err := s.admin.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, grpc.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    domain.MapID,
		Revision: in.Epoch,
	})
	if err != nil {
		glog.Errorf("GetSignedMapRootByRevision(%v, %v): %v", domain.MapID, in.Epoch, err)
		return nil, status.Error(codes.Internal, "Get signed map root failed")
	}

	// Get highest and lowest sequence number.
	meta, err := internal.MetadataFromMapRoot(resp.GetMapRoot())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	highestSeq := uint64(meta.GetHighestFullyCompletedSeq())
	lowestSeq, err := s.lowestSequenceNumber(ctx, domain.MapID, in.PageToken, in.Epoch-1)
	if err != nil {
		return nil, err
	}

	// Read mutations from the database.
	txn, err := s.factory.NewTxn(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewDBTxn(): %v", err)
	}
	maxSequence, mRange, err := s.mutations.ReadRange(txn, domain.MapID, lowestSeq, highestSeq, in.PageSize)
	if err != nil {
		glog.Errorf("mutations.ReadRange(%v, %v, %v): %v", lowestSeq, highestSeq, in.PageSize, err)
		if err := txn.Rollback(); err != nil {
			glog.Errorf("Cannot rollback the transaction: %v", err)
		}
		return nil, status.Error(codes.Internal, "Reading mutations range failed")
	}
	if err := txn.Commit(); err != nil {
		return nil, fmt.Errorf("txn.Commit(): %v", err)
	}
	indexes := make([][]byte, 0, len(mRange))
	mutations := make([]*pb.MutationProof, 0, len(mRange))
	for _, m := range mRange {
		mutations = append(mutations, &pb.MutationProof{Mutation: m.Mutation})
		indexes = append(indexes, m.Mutation.GetIndex())
	}
	// Get leaf proofs.
	// TODO: allow leaf proofs to be optional.
	var epoch int64
	if in.Epoch > 1 {
		epoch = in.Epoch - 1
	} else {
		epoch = 1
	}
	proofs, err := s.inclusionProofs(ctx, in.DomainId, indexes, epoch)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].LeafProof = p
	}

	// MapRevisions start at 1. Log leave's index starts at 1.
	// MapRevision should be at least 1 since the Signer is
	// supposed to create at least one revision on startup.
	respEpoch := resp.GetMapRoot().GetMapRevision()
	// Fetch log proofs.
	logRoot, logConsistency, logInclusion, err := s.logProofs(ctx, domain.LogID, in.GetFirstTreeSize(), respEpoch)
	if err != nil {
		return nil, err
	}

	nextPageToken := ""
	if len(mutations) == int(in.PageSize) && maxSequence != highestSeq {
		nextPageToken = fmt.Sprintf("%d", maxSequence)
	}
	return &pb.GetMutationsResponse{
		Epoch:          in.Epoch,
		Smr:            resp.GetMapRoot(),
		LogRoot:        logRoot.GetSignedLogRoot(),
		LogConsistency: logConsistency.GetProof().GetHashes(),
		LogInclusion:   logInclusion.GetProof().GetHashes(),
		Mutations:      mutations,
		NextPageToken:  nextPageToken,
	}, nil
}

func (s *Server) logProofs(ctx context.Context, logID, firstTreeSize int64, epoch int64) (*tpb.GetLatestSignedLogRootResponse, *tpb.GetConsistencyProofResponse, *tpb.GetInclusionProofResponse, error) {
	// Lookup log and map info.
	logRoot, err := s.tlog.GetLatestSignedLogRoot(ctx,
		&tpb.GetLatestSignedLogRootRequest{
			LogId: logID,
		})
	if err != nil {
		glog.Errorf("tlog.GetLatestSignedLogRoot(%v): %v", logID, err)
		return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch SignedLogRoot")
	}
	secondTreeSize := logRoot.GetSignedLogRoot().GetTreeSize()
	// Consistency proof.
	var logConsistency *tpb.GetConsistencyProofResponse
	if firstTreeSize != 0 {
		logConsistency, err = s.tlog.GetConsistencyProof(ctx,
			&tpb.GetConsistencyProofRequest{
				LogId:          logID,
				FirstTreeSize:  firstTreeSize,
				SecondTreeSize: secondTreeSize,
			})
		if err != nil {
			glog.Errorf("tlog.GetConsistency(%v, %v, %v): %v", logID, firstTreeSize, secondTreeSize, err)
			return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch log consistency proof")
		}
	}
	// Inclusion proof.
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&tpb.GetInclusionProofRequest{
			LogId: logID,
			// SignedMapRoot must be in the log at MapRevision.
			LeafIndex: epoch,
			TreeSize:  secondTreeSize,
		})
	if err != nil {
		glog.Errorf("tlog.GetInclusionProof(%v, %v, %v): %v", logID, epoch, secondTreeSize, err)
		return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch log inclusion proof")
	}
	return logRoot, logConsistency, logInclusion, nil
}

func (s *Server) lowestSequenceNumber(ctx context.Context, mapID int64, token string, epoch int64) (uint64, error) {
	lowestSeq := int64(0)
	if token != "" {
		// A simple cast will panic if the underlying string is not a
		// string. To avoid this, strconv is used.
		var err error
		if lowestSeq, err = strconv.ParseInt(token, 10, 64); err != nil {
			glog.Errorf("strconv.ParseInt(%v, 10, 64): %v", token, err)
			return 0, status.Errorf(codes.InvalidArgument, "%v is not a valid sequence number", token)
		}
	} else if epoch != 0 {
		resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
			MapId:    mapID,
			Revision: epoch,
		})
		if err != nil {
			glog.Errorf("GetSignedMapRootByRevision(%v, %v): %v", mapID, epoch, err)
			return 0, status.Error(codes.Internal, "Get previous signed map root failed")
		}
		meta, err := internal.MetadataFromMapRoot(resp.GetMapRoot())
		if err != nil {
			return 0, status.Error(codes.Internal, err.Error())
		}
		lowestSeq = meta.GetHighestFullyCompletedSeq()
	}
	return uint64(lowestSeq), nil
}

func (s *Server) inclusionProofs(ctx context.Context, domainID string, indexes [][]byte, epoch int64) ([]*tpb.MapLeafInclusion, error) {
	// Lookup log and map info.
	domain, err := s.admin.Read(ctx, domainID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", domainID, err)
		return nil, grpc.Errorf(codes.Internal, "Cannot fetch domain info")
	}
	getResp, err := s.tmap.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    domain.MapID,
		Index:    indexes,
		Revision: epoch,
	})
	if err != nil {
		glog.Errorf("GetLeavesByRevision(): %v", err)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		glog.Errorf("GetLeavesByRevision() len: %v, want %v", got, want)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	return getResp.GetMapLeafInclusion(), nil
}

//
// Streaming RPCs
//

// GetMutationsStream is a streaming API similar to GetMutations.
func (s *Server) GetMutationsStream(in *pb.GetMutationsRequest, stream pb.MutationService_GetMutationsStreamServer) error {
	return grpc.Errorf(codes.Unimplemented, "GetMutationsStream is unimplemented")
}
