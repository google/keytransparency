// Copyright 2017 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"context"
	"fmt"
	"strconv"

	"github.com/google/keytransparency/core/internal"

	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tpb "github.com/google/trillian"
)

var (
	// Size of MutationProof: 2*log_2(accounts) * hash size + account_data ~= 2Kb
	defaultPageSize = int32(16) //32KB
	// Maximum allowed requested page size to prevent DOS.
	maxPageSize = int32(2048) // 8MB
)

// GetEpoch returns a list of mutations paged by epoch number.
func (s *Server) GetEpoch(ctx context.Context, in *pb.GetEpochRequest) (*pb.Epoch, error) {
	if err := validateGetEpochRequest(in); err != nil {
		glog.Errorf("validateGetEpochRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}

	// Lookup log and map info.
	domain, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    domain.MapID,
		Revision: in.Epoch,
	})
	if err != nil {
		glog.Warningf("GetSignedMapRootByRevision(%v, %v): %v", domain.MapID, in.Epoch, err)
		return nil, err
	}

	// MapRevisions start at 0. Log leaf indices starts at 0.
	// MapRevision should be at least 1 since the Signer is
	// supposed to create at least one revision on startup.
	respEpoch := resp.GetMapRoot().GetMapRevision()
	// Fetch log proofs.
	logRoot, logConsistency, logInclusion, err := s.logProofs(ctx, domain.LogID, in.GetFirstTreeSize(), respEpoch)
	if err != nil {
		return nil, err
	}
	return &pb.Epoch{
		DomainId:       in.DomainId,
		Smr:            resp.GetMapRoot(),
		LogRoot:        logRoot.GetSignedLogRoot(),
		LogConsistency: logConsistency.GetProof().GetHashes(),
		LogInclusion:   logInclusion.GetProof().GetHashes(),
	}, nil
}

// GetEpochStream is a streaming API similar to GetMutations.
func (*Server) GetEpochStream(in *pb.GetEpochRequest, stream pb.KeyTransparencyService_GetEpochStreamServer) error {
	return status.Errorf(codes.Unimplemented, "GetEpochStream is unimplemented")
}

// ListMutations returns the mutations that created an epoch.
func (s *Server) ListMutations(ctx context.Context, in *pb.ListMutationsRequest) (*pb.ListMutationsResponse, error) {
	if err := validateListMutationsRequest(in); err != nil {
		glog.Errorf("validateGetMutationsRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}
	// Lookup log and map info.
	domain, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	lowestSeq, err := s.lowestSequenceNumber(ctx, domain.MapID, in.Epoch, in.PageToken)
	if err != nil {
		return nil, err
	}
	highestSeq, err := s.getHighestFullyCompletedSeq(ctx, domain.MapID, in.Epoch)
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
	proofs, err := s.inclusionProofs(ctx, in.DomainId, indexes, in.Epoch-1)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].LeafProof = p
	}

	nextPageToken := ""
	if len(mutations) == int(in.PageSize) && maxSequence != highestSeq {
		nextPageToken = fmt.Sprintf("%d", maxSequence)
	}
	return &pb.ListMutationsResponse{
		Mutations:     mutations,
		NextPageToken: nextPageToken,
	}, nil
}

// ListMutationsStream is a streaming list of mutations in a specific epoch.
func (*Server) ListMutationsStream(in *pb.ListMutationsRequest, stream pb.KeyTransparencyService_ListMutationsStreamServer) error {
	return status.Errorf(codes.Unimplemented, "ListMutationStream is unimplemented")
}

func (s *Server) logProofs(ctx context.Context, logID, firstTreeSize int64, epoch int64) (
	*tpb.GetLatestSignedLogRootResponse,
	*tpb.GetConsistencyProofResponse,
	*tpb.GetInclusionProofResponse,
	error) {
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

// lowestSequenceNumber picks a lower bound on sequence number.
// It returns the max between token and the high water mark of the previous epoch.
func (s *Server) lowestSequenceNumber(ctx context.Context, mapID, epoch int64, token string) (uint64, error) {
	// Pick starting location from token or the last epoch.
	lastSeq, err := s.getHighestFullyCompletedSeq(ctx, mapID, epoch-1)
	if err != nil {
		return 0, err
	}
	tokenSeq, err := s.parseToken(token)
	if err != nil {
		return 0, err
	}
	return max(lastSeq, tokenSeq), nil
}

// getHighestFullyCompletedSeq fetches the map root at epoch and returns
// the highest fully completed sequence number.
func (s *Server) getHighestFullyCompletedSeq(ctx context.Context, mapID, epoch int64) (uint64, error) {
	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    mapID,
		Revision: epoch,
	})
	if err != nil {
		glog.Errorf("GetSignedMapRootByRevision(%v, %v): %v", mapID, epoch, err)
		return 0, status.Error(codes.Internal, "Get signed map root failed")
	}

	// Get highest and lowest sequence number.
	meta, err := internal.MetadataFromMapRoot(resp.GetMapRoot())
	if err != nil {
		return 0, status.Error(codes.Internal, err.Error())
	}

	return uint64(meta.GetHighestFullyCompletedSeq()), nil
}

// parseToken returns the sequence number in token.
// If token is unset, return 0.
func (s *Server) parseToken(token string) (uint64, error) {
	if token == "" {
		return 0, nil
	}
	seq, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		glog.Errorf("strconv.ParseInt(%v, 10, 64): %v", token, err)
		return 0, status.Errorf(codes.InvalidArgument, "%v is not a valid sequence number", token)
	}
	return uint64(seq), nil
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func (s *Server) inclusionProofs(ctx context.Context, domainID string, indexes [][]byte, epoch int64) ([]*tpb.MapLeafInclusion, error) {
	// Lookup log and map info.
	domain, err := s.domains.Read(ctx, domainID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", domainID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
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
