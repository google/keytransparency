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
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"sync"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/water"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	rtpb "github.com/google/keytransparency/core/keyserver/readtoken_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const (
	directoryIDLabel = "directoryid"
	logIDLabel       = "logid"
)

var (
	initMetrics           sync.Once
	watermarkWritten      monitoring.Gauge
	sequencerQueueWritten monitoring.Counter
)

func createMetrics(mf monitoring.MetricFactory) {
	watermarkWritten = mf.NewGauge(
		"keyserver_watermark_written",
		"High watermark of each input log that has been written",
		directoryIDLabel, logIDLabel)
	sequencerQueueWritten = mf.NewCounter(
		"keyserver_queue_written",
		"Counter for each queue row that has been written",
		directoryIDLabel, logIDLabel)
}

// MutationLogs provides sets of roughly time ordered message logs.
type MutationLogs interface {
	// SendBatch submits the whole group of mutations atomically to a given log.
	// Returns the watermark key that the mutation batch got written at. This
	// watermark can be used as a lower bound argument of a ReadLog call. To
	// acquire a watermark to use for the upper bound, use HighWatermark.
	SendBatch(ctx context.Context, directoryID string, logID int64, batch []*pb.EntryUpdate) (water.Mark, error)
	// ReadLog returns the messages in the (low, high] range stored in the
	// specified log. ReadLog always returns complete units of the original
	// batches sent via Send, and will return  more items than limit if
	// needed to do so.
	ReadLog(ctx context.Context, directoryID string, logID int64, low, high water.Mark,
		limit int32) ([]*mutator.LogMessage, error)
	// ListLogs returns a list of logs, optionally filtered by the writable bit.
	ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error)
}

// BatchReader reads batch definitions.
type BatchReader interface {
	// ReadBatch returns the batch definitions for a given revision.
	ReadBatch(ctx context.Context, directoryID string, rev int64) (*spb.MapMetadata, error)
}

// NewFromWrappedKeyFunc returns a vrf private key from a proto.
type NewFromWrappedKeyFunc func(context.Context, proto.Message) (vrf.PrivateKey, error)

// Server holds internal state for the key server.
type Server struct {
	tlog              tpb.TrillianLogClient
	tmap              tpb.TrillianMapClient
	verifyMutation    mutator.VerifyMutationFn
	directories       directory.Storage
	logs              MutationLogs
	batches           BatchReader
	newFromWrappedKey NewFromWrappedKeyFunc
	revisionPageSize  int32
}

// New creates a new instance of the key server.
// revisionPageSize sets the maximum number of map revision to return per list API.
func New(tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	verifyMutation mutator.VerifyMutationFn,
	directories directory.Storage,
	logs MutationLogs,
	batches BatchReader,
	metricsFactory monitoring.MetricFactory,
	revisionPageSize int32,
) *Server {
	initMetrics.Do(func() { createMetrics(metricsFactory) })
	return &Server{
		tlog:              tlog,
		tmap:              tmap,
		verifyMutation:    verifyMutation,
		directories:       directories,
		logs:              logs,
		batches:           batches,
		newFromWrappedKey: p256.NewFromWrappedKey,
		revisionPageSize:  revisionPageSize,
	}
}

// GetUser returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetUser also supports querying past values by setting the revision field.
func (s *Server) GetUser(ctx context.Context, in *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	req := &pb.BatchGetUserRequest{
		DirectoryId:  in.DirectoryId,
		UserIds:      []string{in.UserId},
		LastVerified: in.LastVerified,
	}
	resp, err := s.BatchGetUser(ctx, req)
	if err != nil {
		return nil, logTopLevelErr("GetUser", err)
	}
	if leafCnt := len(resp.MapLeavesByUserId); leafCnt != 1 {
		err := status.Errorf(codes.Internal, "wrong number of map leaves: %v, want 1", leafCnt)
		return nil, logTopLevelErr("GetUser", err)
	}
	leaf, ok := resp.MapLeavesByUserId[in.UserId]
	if !ok {
		return nil, logTopLevelErr("GetUser", status.Errorf(codes.Internal, "wrong leaf returned"))
	}
	ret := &pb.GetUserResponse{
		Revision: resp.Revision,
		Leaf:     leaf,
	}
	return ret, nil
}

// getUserByRevision returns an entry and its proofs.
// getUserByRevision does NOT populate the following fields:
// - LogRoot
// - LogConsistency
func (s *Server) getUserByRevision(ctx context.Context, sth *tpb.SignedLogRoot, d *directory.Directory, userID string,
	rev int64) (*pb.GetUserResponse, error) {
	resp, err := s.batchGetUserByRevision(ctx, sth, d, []string{userID}, rev)
	if err != nil {
		return nil, err
	}
	if len(resp.MapLeavesByUserId) != 1 {
		return nil, status.Errorf(codes.Internal, "wrong number of map leaves: %v, want 1", len(resp.MapLeavesByUserId))
	}
	leaf, ok := resp.MapLeavesByUserId[userID]
	if !ok {
		return nil, status.Errorf(codes.Internal, "wrong leaf returned")
	}
	return &pb.GetUserResponse{
		Revision: resp.Revision,
		Leaf:     leaf,
	}, nil
}

// batchGetUserByRevision returns entries and proofs for a list of users.
func (s *Server) batchGetUserByRevision(ctx context.Context, sth *tpb.SignedLogRoot, d *directory.Directory,
	userIDs []string, mapRevision int64) (*pb.BatchGetUserResponse, error) {
	if mapRevision < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"Revision is %v, want >= 0", mapRevision)
	}

	var root types.LogRootV1
	// TODO(gbelvin): Verify sth first.
	if err := root.UnmarshalBinary(sth.GetLogRoot()); err != nil {
		glog.Errorf("batchGetUserByRevision: root did not unmarshal: %v", err)
		return nil, status.Errorf(codes.Internal, "cannot unmarshal log root")
	}

	indexes := make([][]byte, 0, len(userIDs))
	proofsByUser, usersByIndex, err := s.batchGetUserIndex(ctx, d, userIDs)
	if err != nil {
		return nil, err
	}
	for index := range usersByIndex {
		indexes = append(indexes, []byte(index))
	}
	var getResp *tpb.GetMapLeavesResponse
	if len(indexes) == 1 {
		resp, err := s.tmap.GetLeafByRevision(ctx, &tpb.GetMapLeafByRevisionRequest{
			MapId:    d.Map.TreeId,
			Index:    indexes[0],
			Revision: mapRevision,
		})
		getResp = &tpb.GetMapLeavesResponse{
			MapRoot:          resp.GetMapRoot(),
			MapLeafInclusion: []*tpb.MapLeafInclusion{resp.GetMapLeafInclusion()},
		}
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("GetLeafByRevision(%v, rev: %v): %v", d.Map.TreeId, mapRevision, err)
			return nil, status.Errorf(st.Code(), "Failed fetching map leaf")
		}
	} else {
		getResp, err = s.tmap.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
			MapId:    d.Map.TreeId,
			Index:    indexes,
			Revision: mapRevision,
		})
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("GetLeavesByRevision(%v, rev: %v): %v", d.Map.TreeId, mapRevision, err)
			return nil, status.Errorf(st.Code(), "Failed fetching map leaves")
		}
	}

	if got, want := len(getResp.MapLeafInclusion), len(userIDs); got != want {
		glog.Errorf("GetLeavesByRevision() len: %v, want %v", got, want)
		return nil, status.Errorf(codes.Internal, "Wrong number of map leaves returned")
	}
	leaves := make(map[string]*pb.MapLeaf)
	for _, mapLeafInclusion := range getResp.MapLeafInclusion {
		if mapLeafInclusion.Leaf == nil {
			return nil, status.Errorf(codes.Internal, "leaf is nil")
		}
		var committed *pb.Committed
		if mapLeafInclusion.Leaf.LeafValue != nil {
			extraData := mapLeafInclusion.Leaf.ExtraData
			if extraData == nil {
				return nil, status.Errorf(codes.Internal, "Missing commitment data")
			}
			committed = &pb.Committed{}
			if err := proto.Unmarshal(extraData, committed); err != nil {
				return nil, status.Errorf(codes.Internal, "Cannot read committed value")
			}
		}
		user, ok := usersByIndex[string(mapLeafInclusion.Leaf.GetIndex())]
		if !ok {
			return nil, status.Errorf(codes.Internal, "Returned index %x that was not requested",
				mapLeafInclusion.Leaf.GetIndex())
		}
		proof, ok := proofsByUser[user]
		if !ok {
			return nil, status.Errorf(codes.Internal, "Returned index %x that was not requested",
				mapLeafInclusion.Leaf.GetIndex())
		}

		mapIncl := mapLeafInclusion
		mapIncl.Leaf.Index = nil     // Remove index from the returned data to force clients verify the VRFProof.
		mapIncl.Leaf.ExtraData = nil // Remove extra data as it is a duplicate of Committed.
		leaves[user] = &pb.MapLeaf{
			VrfProof:     proof,
			Committed:    committed,
			MapInclusion: mapIncl,
		}
	}

	// SignedMapHead to SignedLogRoot inclusion proof.
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&tpb.GetInclusionProofRequest{
			LogId: d.Log.TreeId,
			// SignedMapRoot must be placed in the log at MapRevision.
			// MapRevisions start at 0. Log leaves start at 0.
			LeafIndex: mapRevision,
			TreeSize:  int64(root.TreeSize),
		})
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("tlog.GetInclusionProof(%v): %v", d.Log.TreeId, err)
		return nil, status.Errorf(st.Code(), "caannot fetch log inclusion proof: %v", st.Message())
	}

	return &pb.BatchGetUserResponse{
		MapLeavesByUserId: leaves,
		Revision: &pb.Revision{
			MapRoot: &pb.MapRoot{
				MapRoot:      getResp.GetMapRoot(),
				LogInclusion: logInclusion.GetProof().GetHashes(),
			},
		},
	}, nil
}

// BatchGetUser returns a batch of users at the same revision.
func (s *Server) BatchGetUser(ctx context.Context, in *pb.BatchGetUserRequest) (*pb.BatchGetUserResponse, error) {
	if in.DirectoryId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}

	// Lookup log and map info.
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if err != nil {
		return nil, logTopLevelErr("BatchGetUser", err)
	}

	// Fetch latest revision.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, in.GetLastVerified().GetTreeSize())
	if err != nil {
		return nil, logTopLevelErr("BatchGetUser", err)
	}
	revision, err := mapRevisionFor(sth)
	if err != nil {
		errStr := fmt.Sprintf("BatchGetUser - latestRevision(log: %v, sth: %v)", d.Log.TreeId, sth)
		return nil, logTopLevelErr(errStr, err)
	}

	entryProofs, err := s.batchGetUserByRevision(ctx, sth, d, in.UserIds, revision)
	if err != nil {
		return nil, logTopLevelErr("BatchGetUser", err)
	}
	logRoot := &pb.LogRoot{
		LogRoot:        sth,
		LogConsistency: consistencyProof.GetHashes(),
	}
	resp := &pb.BatchGetUserResponse{
		Revision: &pb.Revision{LatestLogRoot: logRoot},
	}
	proto.Merge(resp, entryProofs)
	return resp, nil
}

// BatchGetUserIndex returns indexes for users, computed with a verifiable random function.
func (s *Server) BatchGetUserIndex(ctx context.Context,
	in *pb.BatchGetUserIndexRequest) (*pb.BatchGetUserIndexResponse, error) {
	if in.DirectoryId == "" {
		err := status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
		return nil, logTopLevelErr("BatchGetUserIndex", err)
	}
	d, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		errStr := fmt.Sprintf("BatchGetUserIndex - adminstorage.Read(%v)", in.DirectoryId)
		return nil, logTopLevelErr(errStr, status.Errorf(st.Code(), "Cannot fetch directory info"))
	}
	proofsByUser, _, err := s.batchGetUserIndex(ctx, d, in.UserIds)
	if err != nil {
		return nil, logTopLevelErr("BatchGetUserIndex", err)
	}
	return &pb.BatchGetUserIndexResponse{Proofs: proofsByUser}, nil
}

func (s *Server) batchGetUserIndex(ctx context.Context, d *directory.Directory,
	userIDs []string) (proofsByUser map[string][]byte, usersByIndex map[string]string, err error) {
	vrfPriv, err := s.newFromWrappedKey(ctx, d.VRFPriv)
	if err != nil {
		return nil, nil, err
	}

	type result struct {
		userID string
		index  [32]byte
		proof  []byte
	}
	uIDs := make(chan string)
	results := make(chan result)
	go func() {
		defer close(uIDs)
		for _, userID := range userIDs {
			uIDs <- userID
		}
	}()
	go func() {
		defer close(results)
		var wg sync.WaitGroup
		defer wg.Wait() // Wait before closing results
		for w := 0; w < runtime.NumCPU(); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for userID := range uIDs {
					index, proof := vrfPriv.Evaluate([]byte(userID))
					results <- result{userID, index, proof}
				}
			}()
		}
	}()
	proofsByUser = make(map[string][]byte)
	usersByIndex = make(map[string]string)
	for r := range results {
		proofsByUser[r.userID] = r.proof
		usersByIndex[string(r.index[:])] = r.userID
	}
	return proofsByUser, usersByIndex, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	// Lookup log and map info.
	directoryID := in.GetDirectoryId()
	if directoryID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}
	d, err := s.directories.Read(ctx, directoryID, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("adminstorage.Read(%v): %v", directoryID, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info")
	}

	// Fetch latest revision.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, in.GetLastVerified().GetTreeSize())
	if err != nil {
		return nil, err
	}
	currentRevision, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("latestRevision(log %v, sth%v): %v", d.Log.TreeId, sth, err)
		return nil, err
	}

	if err := validateListEntryHistoryRequest(in, currentRevision); err != nil {
		glog.Errorf("validateListEntryHistoryRequest(%v, %v): %v", in, currentRevision, err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// TODO(gbelvin): fetch all history from trillian at once.
	// Get all GetUserResponse for all revisions in the range [start, start + in.PageSize].
	if in.PageSize > s.revisionPageSize {
		in.PageSize = s.revisionPageSize
	}
	responses := make([]*pb.GetUserResponse, in.PageSize)
	for i := range responses {
		resp, err := s.getUserByRevision(ctx, sth, d, in.UserId, in.Start+int64(i))
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("getUser failed for revision %v: %v", in.Start+int64(i), err)
			return nil, status.Errorf(st.Code(), "GetUser failed")
		}
		proto.Merge(resp, &pb.GetUserResponse{
			Revision: &pb.Revision{
				// TODO(gbelvin): This is redundant and wasteful. Refactor response API.
				LatestLogRoot: &pb.LogRoot{
					LogRoot:        sth,
					LogConsistency: consistencyProof.GetHashes(),
				},
			},
		})
		responses[i] = resp
	}

	nextStart := in.Start + int64(len(responses))
	if nextStart > currentRevision {
		nextStart = 0
	}

	return &pb.ListEntryHistoryResponse{
		Values:    responses,
		NextStart: nextStart,
	}, nil
}

// ListUserRevisions returns a list of revisions covering a period of time.
func (s *Server) ListUserRevisions(ctx context.Context, in *pb.ListUserRevisionsRequest) (
	*pb.ListUserRevisionsResponse, error) {
	pageStart := in.StartRevision
	lastVerified := in.LastVerified
	if in.PageToken != "" {
		token := &rtpb.ListUserRevisionsToken{}
		if err := DecodeToken(in.PageToken, token); err != nil {
			glog.Errorf("invalid page token %v: %v", in.PageToken, err)
			return nil, status.Errorf(codes.InvalidArgument, "Invalid page_token provided")
		}
		// last_verified and page_token are allowed to change between paginated requests.
		// Clear them here both for comparison and for encoding next_page_token in the response.
		in.LastVerified = nil
		in.PageToken = ""
		if !proto.Equal(in, token.Request) {
			return nil, status.Errorf(codes.InvalidArgument, "Request fields changed during pagination")
		}
		pageStart += token.RevisionsReturned
	}

	// Lookup log and map info.
	directoryID := in.DirectoryId
	if directoryID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}
	d, err := s.directories.Read(ctx, directoryID, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("adminstorage.Read(%v): %v", directoryID, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info")
	}

	// Fetch latest log root & consistency proof.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, lastVerified.GetTreeSize())
	if err != nil {
		return nil, err
	}
	newestRevision, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("latestRevision(log %v, sth %v): %v", d.Log.TreeId, sth, err)
		return nil, err
	}

	numRevisions, err := validateListUserRevisionsRequest(in, pageStart, newestRevision)
	if err != nil {
		glog.Errorf("validateListUserRevisionsRequest(%v, %v, %v): %v", in, pageStart, newestRevision, err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// TODO(gbelvin): fetch all history from trillian at once.
	// Get all revisions in the range [start + offset, start + offset + numRevisions].
	revisions := make([]*pb.MapRevision, numRevisions)
	for i := range revisions {
		rev := pageStart + int64(i)
		resp, err := s.getUserByRevision(ctx, sth, d, in.UserId, rev)
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("getUser failed for revision %v: %v", rev, err)
			return nil, status.Errorf(st.Code(), "GetUser failed")
		}
		revisions[i] = &pb.MapRevision{
			MapRoot: resp.GetRevision().GetMapRoot(),
			MapLeaf: resp.GetLeaf(),
		}
	}

	// Add a page token to the response if more revisions can be fetched.
	token := ""
	if pageStart+numRevisions < in.EndRevision {
		tokenProto := &rtpb.ListUserRevisionsToken{
			Request:           in,
			RevisionsReturned: (pageStart - in.StartRevision) + numRevisions,
		}
		token, err = EncodeToken(tokenProto)
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("error encoding page token: %v", err)
			return nil, status.Errorf(st.Code(), "Error encoding pagination token")
		}
	}
	resp := &pb.ListUserRevisionsResponse{
		LatestLogRoot: &pb.LogRoot{
			LogRoot:        sth,
			LogConsistency: consistencyProof.GetHashes(),
		},
		MapRevisions:  revisions,
		NextPageToken: token,
	}
	return resp, nil
}

// BatchListUserRevisions returns a list of revisions covering a period of time.
func (s *Server) BatchListUserRevisions(ctx context.Context, in *pb.BatchListUserRevisionsRequest) (
	*pb.BatchListUserRevisionsResponse, error) {
	pageStart := in.StartRevision
	lastVerified := in.LastVerified

	// Lookup log and map info.
	directoryID := in.DirectoryId
	if directoryID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}
	d, err := s.directories.Read(ctx, directoryID, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("adminstorage.Read(%v): %v", directoryID, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info")
	}

	// Fetch latest log root & consistency proof.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, lastVerified.GetTreeSize())
	if err != nil {
		return nil, err
	}
	newestRevision, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("latestRevision(log %v, sth %v): %v", d.Log.TreeId, sth, err)
		return nil, err
	}

	numRevisions, err := validateBatchListUserRevisionsRequest(in, pageStart, newestRevision)
	if err != nil {
		glog.Errorf("validateBatchListUserRevisionsRequest(%v, %v, %v): %v", in, pageStart, newestRevision, err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// TODO(gbelvin): fetch all history from trillian at once.
	// Get all revisions in the range [start + offset, start + offset + numRevisions].
	revisions := make([]*pb.BatchMapRevision, numRevisions)
	for i := range revisions {
		rev := pageStart + int64(i)
		resp, err := s.batchGetUserByRevision(ctx, sth, d, in.UserIds, rev)
		if st := status.Convert(err); st.Code() != codes.OK {
			glog.Errorf("batchGetUser failed for revision %v: %v", rev, err)
			return nil, status.Errorf(st.Code(), "BatchGetUser failed")
		}
		revisions[i] = &pb.BatchMapRevision{
			MapRoot:           resp.GetRevision().GetMapRoot(),
			MapLeavesByUserId: resp.GetMapLeavesByUserId(),
		}
	}

	resp := &pb.BatchListUserRevisionsResponse{
		LatestLogRoot: &pb.LogRoot{
			LogRoot:        sth,
			LogConsistency: consistencyProof.GetHashes(),
		},
		MapRevisions: revisions,
	}
	return resp, nil
}

// QueueEntryUpdate updates a user's profile. If the user does not exist, a new profile will be created.
func (s *Server) QueueEntryUpdate(ctx context.Context, in *pb.UpdateEntryRequest) (*empty.Empty, error) {
	return s.BatchQueueUserUpdate(ctx, &pb.BatchQueueUserUpdateRequest{
		DirectoryId: in.DirectoryId,
		Updates:     []*pb.EntryUpdate{in.EntryUpdate},
	})
}

// BatchQueueUserUpdate updates a user's profile. If the user does not exist, a new profile will be created.
func (s *Server) BatchQueueUserUpdate(ctx context.Context, in *pb.BatchQueueUserUpdateRequest) (*empty.Empty, error) {
	if in.DirectoryId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}
	// Lookup log and map info.
	directory, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info")
	}
	vrfPriv, err := s.newFromWrappedKey(ctx, directory.VRFPriv)
	if err != nil {
		return nil, err
	}

	// Verify:
	// - Index to Key equality in SignedKV.
	// - Correct profile commitment.
	// - Correct key formats.
	_, tdone := monitoring.StartSpan(ctx, "BatchQueueUserUpdate.verify")
	g, _ := errgroup.WithContext(ctx)
	for _, u := range in.Updates {
		u := u // https://golang.org/doc/faq#closures_and_goroutines
		g.Go(func() error {
			if err := s.verifyMutation(u.Mutation); err != nil {
				glog.Warningf("Invalid UpdateEntryRequest: %v", err)
				return status.Errorf(codes.InvalidArgument, "Invalid mutation")
			}
			if err := validateEntryUpdate(u, vrfPriv); err != nil {
				glog.Warningf("Invalid UpdateEntryRequest: %v", err)
				return status.Errorf(codes.InvalidArgument, "Invalid request")
			}
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	tdone()

	// Pick a random logID.  Note, this effectively picks a random QoS. See issue #1377.
	// TODO(gbelvin): Define an explicit QoS / Load ballancing API.
	wmLogID, err := s.randLog(ctx, directory.DirectoryID)
	if st := status.Convert(err); st.Code() != codes.OK {
		return nil, status.Errorf(st.Code(), "Could not pick a log to write to: %v", err)
	}
	wm, err := s.logs.SendBatch(ctx, directory.DirectoryID, wmLogID, in.Updates)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("mutations.Write failed: %v", err)
		return nil, status.Errorf(st.Code(), "Mutation write error")
	}
	watermarkWritten.Set(float64(wm.Value()), directory.DirectoryID, fmt.Sprintf("%v", wmLogID))
	sequencerQueueWritten.Add(float64(len(in.Updates)), directory.DirectoryID, fmt.Sprintf("%v", wmLogID))
	return &empty.Empty{}, nil
}

func (s *Server) randLog(ctx context.Context, directoryID string) (int64, error) {
	// TODO(gbelvin): Cache these results.
	writable := true
	logIDs, err := s.logs.ListLogs(ctx, directoryID, writable)
	if err != nil {
		return 0, err
	}

	// Return a random log.
	return logIDs[rand.Intn(len(logIDs))], nil
}

// GetDirectory returns all info tied to the specified directory.
//
// This API to get all necessary data needed to verify a particular
// key-server. Data contains for instance the tree-info, like for instance the
// log/map-id and the corresponding public-keys.
func (s *Server) GetDirectory(ctx context.Context, in *pb.GetDirectoryRequest) (*pb.Directory, error) {
	// Lookup log and map info.
	if in.DirectoryId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a directory_id")
	}
	directory, err := s.directories.Read(ctx, in.DirectoryId, false)
	if st := status.Convert(err); st.Code() != codes.OK {
		glog.Errorf("adminstorage.Read(%v): %v", in.DirectoryId, err)
		return nil, status.Errorf(st.Code(), "Cannot fetch directory info for %v", in.DirectoryId)
	}

	return &pb.Directory{
		DirectoryId: directory.DirectoryID,
		Log:         directory.Log,
		Map:         directory.Map,
		Vrf:         directory.VRF,
		MinInterval: ptypes.DurationProto(directory.MinInterval),
		MaxInterval: ptypes.DurationProto(directory.MaxInterval),
	}, nil
}

func logTopLevelErr(rpcName string, err error) error {
	if err != nil {
		glog.Errorf("%v: %v", rpcName, err)
	}
	return err
}
