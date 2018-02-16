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

	"github.com/golang/glog"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/domain"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tpb "github.com/google/trillian"
)

var (
	// Size of MutationProof: 2*log_2(accounts) * hash size + account_data ~= 2Kb
	defaultPageSize = int32(16) //32KB
	// Maximum allowed requested page size to prevent DOS.
	maxPageSize = int32(2048) // 8MB
)

// GetLatestEpoch returns the latest epoch. The current epoch tracks the SignedLogRoot.
func (s *Server) GetLatestEpoch(ctx context.Context, in *pb.GetLatestEpochRequest) (*pb.Epoch, error) {
	// Lookup log and map info.
	d, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("GetLatestEpoch(): adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	// Fetch latest revision.
	sth, err := s.latestLogRoot(ctx, d)
	if err != nil {
		return nil, err
	}
	currentEpoch, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("mapRevisionFor(log %v, sth%v): %v", d.LogID, sth, err)
		return nil, err
	}

	return s.getEpochByRevision(ctx, d, in.GetFirstTreeSize(), currentEpoch)
}

// GetEpoch returns the requested epoch.
func (s *Server) GetEpoch(ctx context.Context, in *pb.GetEpochRequest) (*pb.Epoch, error) {
	if err := validateGetEpochRequest(in); err != nil {
		glog.Errorf("validateGetEpochRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}

	// Lookup log and map info.
	d, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("GetEpoch(): adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	return s.getEpochByRevision(ctx, d, in.GetFirstTreeSize(), in.GetEpoch())

}

func (s *Server) getEpochByRevision(ctx context.Context, d *domain.Domain, firstTreeSize, revision int64) (*pb.Epoch, error) {
	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    d.MapID,
		Revision: revision,
	})
	if err != nil {
		glog.Errorf("GetEpoch(): GetSignedMapRootByRevision(%v, %v): %v", d.MapID, revision, err)
		return nil, err
	}

	// MapRevisions start at 0. Log leaf indices starts at 0.
	// MapRevision should be at least 1 since the Signer is
	// supposed to create at least one revision on startup.
	respEpoch := resp.GetMapRoot().GetMapRevision()
	// Fetch log proofs.
	logProof, err := s.logProofs(ctx, d, firstTreeSize, respEpoch)
	if err != nil {
		return nil, err
	}
	return &pb.Epoch{
		DomainId:       d.DomainID,
		Smr:            resp.GetMapRoot(),
		LogRoot:        logProof.LogRoot,
		LogConsistency: logProof.LogConsistency.GetHashes(),
		LogInclusion:   logProof.LogInclusion.GetHashes(),
	}, nil
}

// GetEpochStream is a streaming API similar to ListMutations.
func (*Server) GetEpochStream(in *pb.GetEpochRequest, stream pb.KeyTransparency_GetEpochStreamServer) error {
	return status.Error(codes.Unimplemented, "GetEpochStream is unimplemented")
}

// ListMutations returns the mutations that created an epoch.
func (s *Server) ListMutations(ctx context.Context, in *pb.ListMutationsRequest) (*pb.ListMutationsResponse, error) {
	if err := validateListMutationsRequest(in); err != nil {
		glog.Errorf("validateListMutationsRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}
	// Lookup log and map info.
	d, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("ListMutations(): adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	start, err := parseToken(in.PageToken)
	if err != nil {
		return nil, err
	}
	// Read mutations from the database.
	max, entries, err := s.mutations.ReadPage(ctx, d.DomainID, in.GetEpoch(), start, in.GetPageSize())
	if err != nil {
		glog.Errorf("ListMutations(): mutations.ReadRange(%v, %v, %v, %v): %v", d.MapID, in.GetEpoch(), start, in.GetPageSize(), err)
		return nil, status.Error(codes.Internal, "Reading mutations range failed")
	}
	indexes := make([][]byte, 0, len(entries))
	mutations := make([]*pb.MutationProof, 0, len(entries))
	for _, e := range entries {
		mutations = append(mutations, &pb.MutationProof{Mutation: e})
		indexes = append(indexes, e.GetIndex())
	}
	// Get leaf proofs.
	proofs, err := s.inclusionProofs(ctx, d, indexes, in.Epoch-1)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].LeafProof = p
	}

	nextPageToken := ""
	if len(mutations) == int(in.PageSize) {
		nextPageToken = fmt.Sprintf("%d", max+1)
	}
	return &pb.ListMutationsResponse{
		Mutations:     mutations,
		NextPageToken: nextPageToken,
	}, nil
}

// ListMutationsStream is a streaming list of mutations in a specific epoch.
func (*Server) ListMutationsStream(in *pb.ListMutationsRequest, stream pb.KeyTransparency_ListMutationsStreamServer) error {
	return status.Error(codes.Unimplemented, "ListMutationStream is unimplemented")
}

// logProof holds the proof for a signed map root up to signed log root.
type logProof struct {
	LogRoot        *tpb.SignedLogRoot
	LogConsistency *tpb.Proof
	LogInclusion   *tpb.Proof
}

// logProofs returns the proofs for a given epoch.
func (s *Server) logProofs(ctx context.Context, d *domain.Domain, firstTreeSize int64, epoch int64) (*logProof, error) {
	logRoot, logConsistency, err := s.latestLogRootProof(ctx, d, firstTreeSize)
	if err != nil {
		return nil, err
	}

	// Inclusion proof.
	secondTreeSize := logRoot.GetTreeSize()
	if epoch >= secondTreeSize {
		return nil, status.Errorf(codes.NotFound, "keyserver: Epoch %v has not been released yet", epoch)
	}
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&tpb.GetInclusionProofRequest{
			LogId: d.LogID,
			// SignedMapRoot must be in the log at MapRevision.
			LeafIndex: epoch,
			TreeSize:  secondTreeSize,
		})
	if err != nil {
		glog.Errorf("logProofs(): log.GetInclusionProof(%v, %v, %v): %v", d.LogID, epoch, secondTreeSize, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch log inclusion proof: %v", err)
	}
	return &logProof{
		LogRoot:        logRoot,
		LogConsistency: logConsistency,
		LogInclusion:   logInclusion.GetProof(),
	}, nil
}

func (s *Server) latestLogRoot(ctx context.Context, d *domain.Domain) (*tpb.SignedLogRoot, error) {
	// Fresh Root.
	logRoot, err := s.tlog.GetLatestSignedLogRoot(ctx,
		&tpb.GetLatestSignedLogRootRequest{
			LogId: d.LogID,
		})
	if err != nil {
		glog.Errorf("tlog.GetLatestSignedLogRoot(%v): %v", d.LogID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch SignedLogRoot")
	}
	sth := logRoot.GetSignedLogRoot()
	return sth, nil
}

// latestLogRootProof returns the latest SignedLogRoot and it's consistency proof.
func (s *Server) latestLogRootProof(ctx context.Context, d *domain.Domain, firstTreeSize int64) (*tpb.SignedLogRoot, *tpb.Proof, error) {

	sth, err := s.latestLogRoot(ctx, d)
	if err != nil {
		return nil, nil, err
	}
	// Consistency proof.
	secondTreeSize := sth.GetTreeSize()
	var logConsistency *tpb.GetConsistencyProofResponse
	if firstTreeSize != 0 {
		logConsistency, err = s.tlog.GetConsistencyProof(ctx,
			&tpb.GetConsistencyProofRequest{
				LogId:          d.LogID,
				FirstTreeSize:  firstTreeSize,
				SecondTreeSize: secondTreeSize,
			})
		if err != nil {
			glog.Errorf("latestLogRootProof(): log.GetConsistency(%v, %v, %v): %v",
				d.LogID, firstTreeSize, secondTreeSize, err)
			return nil, nil, status.Errorf(codes.Internal, "Cannot fetch log consistency proof")
		}
	}
	return sth, logConsistency.GetProof(), nil
}

// mapRevisionFor returns the latest map revision, given the latest sth.
// The log is the authoritative source of the latest revision.
func mapRevisionFor(sth *tpb.SignedLogRoot) (int64, error) {
	treeSize := sth.GetTreeSize()
	// TreeSize = max_index + 1 because the log starts at index 0.
	maxIndex := treeSize - 1

	// The revision of the map is its index in the log.
	if maxIndex < 0 {
		return 0, status.Errorf(codes.Internal, "log is uninitialized")
	}
	return maxIndex, nil
}

// parseToken returns the sequence number in token.
// If token is unset, return 0.
func parseToken(token string) (int64, error) {
	if token == "" {
		return 0, nil
	}
	seq, err := strconv.ParseInt(token, 10, 64)
	if err != nil {
		glog.Errorf("parseToken(%v): strconv.ParseInt(): %v", token, err)
		return 0, status.Errorf(codes.InvalidArgument, "%v is not a valid sequence number", token)
	}
	return seq, nil
}

func (s *Server) inclusionProofs(ctx context.Context, d *domain.Domain, indexes [][]byte, epoch int64) ([]*tpb.MapLeafInclusion, error) {
	getResp, err := s.tmap.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    d.MapID,
		Index:    indexes,
		Revision: epoch,
	})
	if err != nil {
		glog.Errorf("inclusionProofs(): GetLeavesByRevision(): %v", err)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		glog.Errorf("inclusionProofs(): GetLeavesByRevision() len: %v, want %v", got, want)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	return getResp.GetMapLeafInclusion(), nil
}
