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

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/mutator"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
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
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if err != nil {
		glog.Errorf("GetLatestEpoch(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info")
	}

	// Fetch latest revision.
	sth, logConsistency, err := s.latestLogRootProof(ctx, d, in.GetLastVerifiedTreeSize())
	if err != nil {
		return nil, err
	}

	currentEpoch, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("mapRevisionFor(log %v, sth%v): %v", d.LogID, sth, err)
		return nil, err
	}

	return s.getEpochByRevision(ctx, d, sth, logConsistency, currentEpoch)
}

// GetEpoch returns the requested epoch.
func (s *Server) GetEpoch(ctx context.Context, in *pb.GetEpochRequest) (*pb.Epoch, error) {
	if err := validateGetEpochRequest(in); err != nil {
		glog.Errorf("validateGetEpochRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}

	// Lookup log and map info.
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if err != nil {
		glog.Errorf("GetEpoch(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info")
	}

	logRoot, logConsistency, err := s.latestLogRootProof(ctx, d, in.GetLastVerifiedTreeSize())
	if err != nil {
		return nil, err
	}

	return s.getEpochByRevision(ctx, d, logRoot, logConsistency, in.GetEpoch())

}

func (s *Server) getEpochByRevision(ctx context.Context, d *directory.Directory,
	logRoot *tpb.SignedLogRoot, logConsistency *tpb.Proof, mapRevision int64) (*pb.Epoch, error) {
	logInclusion, err := s.logInclusion(ctx, d, logRoot, mapRevision)
	if err != nil {
		return nil, err
	}
	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    d.MapID,
		Revision: mapRevision,
	})
	if err != nil {
		glog.Errorf("GetEpoch(): GetSignedMapRootByRevision(%v, %v): %v", d.MapID, mapRevision, err)
		return nil, err
	}

	return &pb.Epoch{
		DirectoryId:    d.DirectoryID,
		MapRoot:        resp.GetMapRoot(),
		LogRoot:        logRoot,
		LogConsistency: logConsistency.GetHashes(),
		LogInclusion:   logInclusion.GetHashes(),
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
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if err != nil {
		glog.Errorf("ListMutations(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch directory info")
	}
	meta, err := s.batches.ReadBatch(ctx, in.DirectoryId, in.Epoch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ReadBatch(%v, %v): %v", in.DirectoryId, in.Epoch, err)
	}
	rt, err := SourceMap(meta.Sources).ParseToken(in.PageToken)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed parsing page_token: %v: %v", in.PageToken, err)
	}

	// Read PageSize + 1 messages from the log to see if there is another page.
	high := meta.Sources[rt.ShardId].HighestWatermark
	msgs, err := s.logs.ReadLog(ctx, d.DirectoryID, rt.ShardId, rt.LowWatermark, high, in.PageSize+1)
	if err != nil {
		glog.Errorf("ListMutations(): ReadLog(%v, log: %v/(%v, %v], batchSize: %v): %v",
			d.DirectoryID, rt.ShardId, rt.LowWatermark, high, in.PageSize, err)
		return nil, status.Error(codes.Internal, "Reading mutations range failed")
	}
	moreInLogID := len(msgs) == int(in.PageSize+1)
	var lastRow *mutator.LogMessage
	if moreInLogID {
		msgs = msgs[0:in.PageSize]    // Only return PageSize messages.
		lastRow = msgs[in.PageSize-1] // Next start is the last row of this batch.
	}

	// For each msg, attach the leaf value from the previous map revision.
	// This will allow the client to re-run the mutation for themselves.
	indexes := make([][]byte, 0, len(msgs))
	mutations := make([]*pb.MutationProof, 0, len(msgs))
	for _, m := range msgs {
		mutations = append(mutations, &pb.MutationProof{Mutation: m.Mutation})
		var entry pb.Entry
		if err := proto.Unmarshal(m.Mutation.Entry, &entry); err != nil {
			return nil, status.Errorf(codes.DataLoss, "could not unmarshal entry")
		}
		indexes = append(indexes, entry.GetIndex())
	}
	proofs, err := s.inclusionProofs(ctx, d, indexes, in.Epoch-1)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].LeafProof = p
	}
	nextToken, err := EncodeToken(SourceMap(meta.Sources).Next(rt, lastRow))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Failed creating next token: %v", err)

	}
	return &pb.ListMutationsResponse{
		Mutations:     mutations,
		NextPageToken: nextToken,
	}, nil
}

// ListMutationsStream is a streaming list of mutations in a specific epoch.
func (*Server) ListMutationsStream(in *pb.ListMutationsRequest, stream pb.KeyTransparency_ListMutationsStreamServer) error {
	return status.Error(codes.Unimplemented, "ListMutationStream is unimplemented")
}

// logInclusion returns the inclusion proof for a map revision in the log of map roots.
func (s *Server) logInclusion(ctx context.Context, d *directory.Directory, logRoot *tpb.SignedLogRoot, epoch int64) (
	*tpb.Proof, error) {
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
		glog.Errorf("log.GetInclusionProof(%v, %v, %v): %v", d.LogID, epoch, secondTreeSize, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch log inclusion proof: %v", err)
	}
	return logInclusion.GetProof(), nil

}

func (s *Server) latestLogRoot(ctx context.Context, d *directory.Directory) (*tpb.SignedLogRoot, error) {
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
func (s *Server) latestLogRootProof(ctx context.Context, d *directory.Directory, firstTreeSize int64) (
	*tpb.SignedLogRoot, *tpb.Proof, error) {

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

func (s *Server) inclusionProofs(ctx context.Context, d *directory.Directory, indexes [][]byte, epoch int64) (
	[]*tpb.MapLeafInclusion, error) {
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
