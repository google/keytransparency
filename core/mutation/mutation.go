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

// Package mutation implements the monitor service. This package contains the
// core functionality.
package mutation

import (
	"fmt"
	"strconv"

	"github.com/golang/glog"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"

	"golang.org/x/net/context"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian"
)

// Server holds internal state for the monitor server core functionality.
type Server struct {
	logID     int64
	mapID     int64
	tlog      trillian.TrillianLogClient
	tmap      trillian.TrillianMapClient
	mutations mutator.Mutation
	factory   transaction.Factory
}

// New creates a new instance of the monitor server.
func New(logID int64,
	mapID int64,
	tlog trillian.TrillianLogClient,
	tmap trillian.TrillianMapClient,
	mutations mutator.Mutation,
	factory transaction.Factory) *Server {
	return &Server{
		logID:     logID,
		mapID:     mapID,
		tlog:      tlog,
		tmap:      tmap,
		mutations: mutations,
		factory:   factory,
	}
}

// GetMutations returns a list of mutations paged by epoch number.
func (s *Server) GetMutations(ctx context.Context, in *tpb.GetMutationsRequest) (*tpb.GetMutationsResponse, error) {
	if err := validateGetMutationsRequest(in); err != nil {
		glog.Errorf("validateGetMutationsRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}
	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &trillian.GetSignedMapRootByRevisionRequest{
		MapId:    s.mapID,
		Revision: in.Epoch,
	})
	if err != nil {
		glog.Errorf("GetSignedMapRootByRevision(%v, %v): %v", s.mapID, in.Epoch, err)
		return nil, status.Error(codes.Internal, "Get signed map root failed")
	}

	// Get highest and lowest sequence number.
	meta, err := internal.MetadataFromMapRoot(resp.GetMapRoot())
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	highestSeq := uint64(meta.GetHighestFullyCompletedSeq())
	lowestSeq, err := s.lowestSequenceNumber(ctx, in.PageToken, in.Epoch-1)
	if err != nil {
		return nil, err
	}

	// Read mutations from the database.
	txn, err := s.factory.NewTxn(ctx)
	if err != nil {
		return nil, fmt.Errorf("NewDBTxn(): %v", err)
	}
	maxSequence, mRange, err := s.mutations.ReadRange(txn, lowestSeq, highestSeq, in.PageSize)
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
	mutations := make([]*tpb.Mutation, 0, len(mRange))
	for _, m := range mRange {
		mutations = append(mutations, &tpb.Mutation{Update: m})
		indexes = append(indexes, m.GetKeyValue().GetKey())
	}
	// Get leaf proofs.
	// TODO: allow leaf proofs to be optional.
	var epoch int64
	if in.Epoch > 1 {
		epoch = in.Epoch - 1
	} else {
		epoch = 1
	}
	proofs, err := s.inclusionProofs(ctx, indexes, epoch)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].Proof = p
	}

	// MapRevisions start at 1. Log leave's index starts at 1.
	// MapRevision should be at least 1 since the Signer is
	// supposed to create at least one revision on startup.
	respEpoch := resp.GetMapRoot().GetMapRevision()
	// Fetch log proofs.
	logRoot, logConsistency, logInclusion, err := s.logProofs(ctx, in.GetFirstTreeSize(), respEpoch)
	if err != nil {
		return nil, err
	}

	nextPageToken := ""
	if len(mutations) == int(in.PageSize) && maxSequence != highestSeq {
		nextPageToken = fmt.Sprintf("%d", maxSequence)
	}
	return &tpb.GetMutationsResponse{
		Epoch:          in.Epoch,
		Smr:            resp.GetMapRoot(),
		LogRoot:        logRoot.GetSignedLogRoot(),
		LogConsistency: logConsistency.GetProof().GetHashes(),
		LogInclusion:   logInclusion.GetProof().GetHashes(),
		Mutations:      mutations,
		NextPageToken:  nextPageToken,
	}, nil
}

func (s *Server) logProofs(ctx context.Context, firstTreeSize int64, epoch int64) (*trillian.GetLatestSignedLogRootResponse, *trillian.GetConsistencyProofResponse, *trillian.GetInclusionProofResponse, error) {
	logRoot, err := s.tlog.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId: s.logID,
		})
	if err != nil {
		glog.Errorf("tlog.GetLatestSignedLogRoot(%v): %v", s.logID, err)
		return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch SignedLogRoot")
	}
	secondTreeSize := logRoot.GetSignedLogRoot().GetTreeSize()
	// Consistency proof.
	var logConsistency *trillian.GetConsistencyProofResponse
	if firstTreeSize != 0 {
		logConsistency, err = s.tlog.GetConsistencyProof(ctx,
			&trillian.GetConsistencyProofRequest{
				LogId:          s.logID,
				FirstTreeSize:  firstTreeSize,
				SecondTreeSize: secondTreeSize,
			})
		if err != nil {
			glog.Errorf("tlog.GetConsistency(%v, %v, %v): %v", s.logID, firstTreeSize, secondTreeSize, err)
			return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch log consistency proof")
		}
	}
	// Inclusion proof.
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&trillian.GetInclusionProofRequest{
			LogId: s.logID,
			// SignedMapRoot must be in the log at MapRevision.
			LeafIndex: epoch,
			TreeSize:  secondTreeSize,
		})
	if err != nil {
		glog.Errorf("tlog.GetInclusionProof(%v, %v, %v): %v", s.logID, epoch, secondTreeSize, err)
		return nil, nil, nil, status.Error(codes.Internal, "Cannot fetch log inclusion proof")
	}
	return logRoot, logConsistency, logInclusion, nil
}

func (s *Server) lowestSequenceNumber(ctx context.Context, token string, epoch int64) (uint64, error) {
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
		resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &trillian.GetSignedMapRootByRevisionRequest{
			MapId:    s.mapID,
			Revision: epoch,
		})
		if err != nil {
			glog.Errorf("GetSignedMapRootByRevision(%v, %v): %v", s.mapID, epoch, err)
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

func (s *Server) inclusionProofs(ctx context.Context, indexes [][]byte, epoch int64) ([]*trillian.MapLeafInclusion, error) {
	getResp, err := s.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId:    s.mapID,
		Index:    indexes,
		Revision: epoch,
	})
	if err != nil {
		glog.Errorf("GetLeaves(): %v", err)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		glog.Errorf("GetLeaves() len: %v, want %v", got, want)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	return getResp.GetMapLeafInclusion(), nil
}
