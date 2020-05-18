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
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/sequencer/metadata"
	"github.com/google/keytransparency/core/water"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

var (
	// Size of MutationProof: 2*log_2(accounts) * hash size + account_data ~= 2Kb
	defaultPageSize = int32(16) //32KB
	// Maximum allowed requested page size to prevent DOS.
	maxPageSize = int32(2048) // 8MB
)

// GetLatestRevision returns the latest revision. The current revision tracks the SignedLogRoot.
func (s *Server) GetLatestRevision(ctx context.Context, in *pb.GetLatestRevisionRequest) (*pb.Revision, error) {
	// Lookup log and map info.
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("GetLatestRevision(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info: %v", st.Message())
	}

	// Fetch latest revision.
	sth, logConsistency, err := s.latestLogRootProof(ctx, d, in.GetLastVerified().GetTreeSize())
	if err != nil {
		return nil, err
	}

	currentRevision, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("mapRevisionFor(log %v, sth%v): %v", d.Log.TreeId, sth, err)
		return nil, err
	}

	return s.getRevisionByRevision(ctx, d, sth, logConsistency, currentRevision)
}

// GetRevision returns the requested revision.
func (s *Server) GetRevision(ctx context.Context, in *pb.GetRevisionRequest) (*pb.Revision, error) {
	if err := validateGetRevisionRequest(in); err != nil {
		glog.Errorf("validateGetRevisionRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}

	// Lookup log and map info.
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("GetRevision(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info %v", st.Message())
	}

	logRoot, logConsistency, err := s.latestLogRootProof(ctx, d, in.GetLastVerified().GetTreeSize())
	if err != nil {
		return nil, err
	}

	return s.getRevisionByRevision(ctx, d, logRoot, logConsistency, in.GetRevision())
}

func (s *Server) getRevisionByRevision(ctx context.Context, d *directory.Directory,
	logRoot *tpb.SignedLogRoot, logConsistency *tpb.Proof, mapRevision int64) (*pb.Revision, error) {
	logInclusion, err := s.logInclusion(ctx, d, logRoot, mapRevision)
	if err != nil {
		return nil, err
	}
	// Get signed map root by revision.
	resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
		MapId:    d.Map.TreeId,
		Revision: mapRevision,
	})
	if err != nil {
		glog.Errorf("GetRevision(): GetSignedMapRootByRevision(%v, %v): %v", d.Map.TreeId, mapRevision, err)
		return nil, err
	}

	return &pb.Revision{
		DirectoryId: d.DirectoryID,
		MapRoot: &pb.MapRoot{
			MapRoot:      resp.GetMapRoot(),
			LogInclusion: logInclusion.GetHashes(),
		},
		LatestLogRoot: &pb.LogRoot{
			LogRoot:        logRoot,
			LogConsistency: logConsistency.GetHashes(),
		},
	}, nil
}

// GetRevisionStream is a streaming API similar to ListMutations.
func (*Server) GetRevisionStream(in *pb.GetRevisionRequest, stream pb.KeyTransparency_GetRevisionStreamServer) error {
	return status.Error(codes.Unimplemented, "GetRevisionStream is unimplemented")
}

// ListMutations returns the mutations that created an revision.
func (s *Server) ListMutations(ctx context.Context, in *pb.ListMutationsRequest) (*pb.ListMutationsResponse, error) {
	if err := validateListMutationsRequest(in); err != nil {
		glog.Errorf("validateListMutationsRequest(%v): %v", in, err)
		return nil, status.Error(codes.InvalidArgument, "Invalid request")
	}
	// Lookup log and map info.
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("ListMutations(): adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info: %v", st.Message())
	}
	meta, err := s.batches.ReadBatch(ctx, in.DirectoryId, in.Revision)
	if st := status.Convert(err); st.Code() != codes.OK {
		return nil, status.Errorf(st.Code(), "ReadBatch(%v, %v): %v", in.DirectoryId, in.Revision, st.Message())
	}
	rt, err := SourceList(meta.Sources).ParseToken(in.PageToken)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Failed parsing page_token: %v: %v", in.PageToken, err)
	}

	// Read PageSize + 1 messages from the log to see if there is another page.
	high := metadata.FromProto(meta.Sources[rt.SliceIndex]).HighMark()
	logID := meta.Sources[rt.SliceIndex].LogId
	low := water.NewMark(rt.StartWatermark)
	msgs, err := s.logs.ReadLog(ctx, d.DirectoryID, logID, low, high, in.PageSize+1)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("ListMutations(): ReadLog(%v, log: %v/(%v, %v], batchSize: %v): %v",
			d.DirectoryID, logID, low, high, in.PageSize, err)
		return nil, status.Errorf(st.Code(), "Reading mutations range failed: %v", st.Message())
	}
	moreInLogID := len(msgs) == int(in.PageSize+1)
	var lastRow *mutator.LogMessage
	if moreInLogID {
		lastRow = msgs[in.PageSize] // Next start is the last row of this batch.
		msgs = msgs[0:in.PageSize]  // Only return PageSize messages.
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
	proofs, err := s.inclusionProofs(ctx, d, indexes, in.Revision-1)
	if err != nil {
		return nil, err
	}
	for i, p := range proofs {
		mutations[i].LeafProof = p
	}
	nextToken, err := EncodeToken(SourceList(meta.Sources).Next(rt, lastRow))
	if st := status.Convert(err); st.Code() != codes.OK {
		return nil, status.Errorf(st.Code(), "Failed creating next token: %v", st.Message())
	}
	return &pb.ListMutationsResponse{
		Mutations:     mutations,
		NextPageToken: nextToken,
	}, nil
}

// ListMutationsStream is a streaming list of mutations in a specific revision.
func (*Server) ListMutationsStream(in *pb.ListMutationsRequest, stream pb.KeyTransparency_ListMutationsStreamServer) error {
	return status.Error(codes.Unimplemented, "ListMutationStream is unimplemented")
}

// logInclusion returns the inclusion proof for a map revision in the log of map roots.
func (s *Server) logInclusion(ctx context.Context, d *directory.Directory, logRoot *tpb.SignedLogRoot, revision int64) (
	*tpb.Proof, error) {
	// Inclusion proof.
	// TODO(gbelvin): Verify root.
	var root types.LogRootV1
	if err := root.UnmarshalBinary(logRoot.GetLogRoot()); err != nil {
		return nil, status.Errorf(codes.Internal, "keyserver: Failed to unmarshal log root: %v", err)
	}
	secondTreeSize := int64(root.TreeSize)
	if revision >= secondTreeSize {
		return nil, status.Errorf(codes.NotFound, "keyserver: Revision %v has not been released yet", revision)
	}
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&tpb.GetInclusionProofRequest{
			LogId: d.Log.TreeId,
			// SignedMapRoot must be in the log at MapRevision.
			LeafIndex: revision,
			TreeSize:  secondTreeSize,
		})
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("log.GetInclusionProof(%v, %v, %v): %v", d.Log.TreeId, revision, secondTreeSize, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch log inclusion proof: %v", st.Message())
	}
	return logInclusion.GetProof(), nil
}

func (s *Server) latestLogRootProof(ctx context.Context, d *directory.Directory, firstTreeSize int64) (
	*tpb.SignedLogRoot, *tpb.Proof, error) {
	resp, err := s.tlog.GetLatestSignedLogRoot(ctx,
		&tpb.GetLatestSignedLogRootRequest{
			LogId:         d.Log.TreeId,
			FirstTreeSize: firstTreeSize,
		})
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("tlog.GetLatestSignedLogRoot(%v): %v", d.Log.TreeId, err)
		return nil, nil, status.Errorf(st.Code(), "Cannot fetch SignedLogRoot: %v", st.Message())
	}
	return resp.GetSignedLogRoot(), resp.GetProof(), nil
}

// mapRevisionFor returns the latest map revision, given the latest sth.
// The log is the authoritative source of the latest revision.
func mapRevisionFor(sth *tpb.SignedLogRoot) (int64, error) {
	// TODO(gbelvin): Verify root.
	var root types.LogRootV1
	if err := root.UnmarshalBinary(sth.GetLogRoot()); err != nil {
		return 0, status.Errorf(codes.Internal, "mapRevisionFor: Failed to unmarshal log root: %v", err)
	}
	treeSize := int64(root.TreeSize)
	// TreeSize = max_index + 1 because the log starts at index 0.
	maxIndex := treeSize - 1

	// The revision of the map is its index in the log.
	if maxIndex < 0 {
		return 0, status.Errorf(codes.Internal, "log is uninitialized")
	}
	return maxIndex, nil
}

func (s *Server) inclusionProofs(ctx context.Context, d *directory.Directory, indexes [][]byte, revision int64) (
	[]*tpb.MapLeafInclusion, error) {
	getResp, err := s.tmap.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    d.Map.TreeId,
		Index:    indexes,
		Revision: revision,
	})
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("inclusionProofs(): GetLeavesByRevision(): %v", err)
		return nil, status.Errorf(st.Code(), "Failed fetching map leaf: %v", st.Message())
	}
	if got, want := len(getResp.GetMapLeafInclusion()), len(indexes); got != want {
		glog.Errorf("inclusionProofs(): GetLeavesByRevision() len: %v, want %v", got, want)
		return nil, status.Error(codes.Internal, "Failed fetching map leaf")
	}
	return getResp.GetMapLeafInclusion(), nil
}
