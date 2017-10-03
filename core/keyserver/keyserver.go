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
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/authorization"
	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/transaction"

	"github.com/golang/glog"
	"github.com/google/trillian/crypto/keys/der"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	authzpb "github.com/google/keytransparency/core/proto/authorization"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1"
	"github.com/google/trillian"
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
	logID     int64
	tlog      trillian.TrillianLogClient
	mapID     int64
	tmap      trillian.TrillianMapClient
	tadmin    trillian.TrillianAdminClient
	committer commitments.Committer
	auth      authentication.Authenticator
	authz     authorization.Authorization
	vrf       vrf.PrivateKey
	mutator   mutator.Mutator
	factory   transaction.Factory
	mutations mutator.Mutation
}

// New creates a new instance of the key server.
func New(logID int64,
	tlog trillian.TrillianLogClient,
	mapID int64,
	tmap trillian.TrillianMapClient,
	tadmin trillian.TrillianAdminClient,
	committer commitments.Committer,
	vrf vrf.PrivateKey,
	mutator mutator.Mutator,
	auth authentication.Authenticator,
	authz authorization.Authorization,
	factory transaction.Factory,
	mutations mutator.Mutation) *Server {
	return &Server{
		logID:     logID,
		tlog:      tlog,
		mapID:     mapID,
		tmap:      tmap,
		tadmin:    tadmin,
		committer: committer,
		vrf:       vrf,
		mutator:   mutator,
		auth:      auth,
		authz:     authz,
		factory:   factory,
		mutations: mutations,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
	return s.getEntry(ctx, in.UserId, in.AppId, in.FirstTreeSize, -1)
}

func (s *Server) getEntry(ctx context.Context, userID, appID string, firstTreeSize, revision int64) (*pb.GetEntryResponse, error) {
	if revision == 0 {
		return nil, grpc.Errorf(codes.InvalidArgument,
			"Epoch 0 is inavlid. The first map revision is epoch 1.")
	}

	// Fresh Root.
	logRoot, err := s.tlog.GetLatestSignedLogRoot(ctx,
		&trillian.GetLatestSignedLogRootRequest{
			LogId: s.logID,
		})
	if err != nil {
		glog.Errorf("tlog.GetLatestSignedLogRoot(%v): %v", s.logID, err)
		return nil, grpc.Errorf(codes.Internal, "Cannot fetch SignedLogRoot")
	}
	// Use the log as the athoritative source of the latest revision.
	if revision < 0 {
		// The maximum index in the log is one minus the number of items in the log.
		revision = logRoot.GetSignedLogRoot().GetTreeSize() - 1
	}

	// VRF.
	index, proof := s.vrf.Evaluate(vrf.UniqueID(userID, appID))

	getResp, err := s.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId:    s.mapID,
		Index:    [][]byte{index[:]},
		Revision: revision,
	})
	if err != nil {
		glog.Errorf("GetLeaves(): %v", err)
		return nil, grpc.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.MapLeafInclusion), 1; got != want {
		glog.Errorf("GetLeaves() len: %v, want %v", got, want)
		return nil, grpc.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	neighbors := getResp.MapLeafInclusion[0].Inclusion
	leaf := getResp.MapLeafInclusion[0].Leaf.LeafValue

	var committed *pb.Committed
	if leaf != nil {
		e, err := entry.FromLeafValue(leaf)
		if err != nil {
			return nil, grpc.Errorf(codes.Internal, "Cannot decode leaf value")
		}

		data, nonce, err := s.committer.Read(ctx, e.GetCommitment())
		if err != nil {
			glog.Errorf("Cannot read committed value: %v", err)
			return nil, grpc.Errorf(codes.Internal, "Cannot read committed value")
		}
		if data == nil {
			return nil, grpc.Errorf(codes.NotFound, "Commitment %v not found", e.GetCommitment())
		}
		committed = &pb.Committed{
			Key:  nonce,
			Data: data,
		}
	}

	// Fetch log proofs.
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
			glog.Errorf("tlog.GetConsistency(%v, %v, %v): %v",
				s.logID, firstTreeSize, secondTreeSize, err)
			return nil, grpc.Errorf(codes.Internal, "Cannot fetch log consistency proof")
		}
	}

	// Inclusion proof.
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&trillian.GetInclusionProofRequest{
			LogId: s.logID,
			// SignedMapRoot must be placed in the log at MapRevision.
			// MapRevisions start at 1. Log leaves start at 1.
			LeafIndex: getResp.GetMapRoot().GetMapRevision(),
			TreeSize:  secondTreeSize,
		})
	if err != nil {
		glog.Errorf("tlog.GetInclusionProof(%v, %v, %v): %v",
			s.logID, getResp.GetMapRoot().GetMapRevision(), secondTreeSize, err)
		return nil, grpc.Errorf(codes.Internal, "Cannot fetch log inclusion proof")
	}

	return &pb.GetEntryResponse{
		VrfProof:  proof,
		Committed: committed,
		LeafProof: &trillian.MapLeafInclusion{
			Inclusion: neighbors,
			Leaf: &trillian.MapLeaf{
				LeafValue: leaf,
			},
		},
		Smr:            getResp.GetMapRoot(),
		LogRoot:        logRoot.GetSignedLogRoot(),
		LogConsistency: logConsistency.GetProof().GetHashes(),
		LogInclusion:   logInclusion.GetProof().GetHashes(),
	}, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	// Get current epoch.
	resp, err := s.tmap.GetSignedMapRoot(ctx, &trillian.GetSignedMapRootRequest{
		MapId: s.mapID,
	})
	if err != nil {
		glog.Errorf("GetSignedMapRoot(%v): %v", s.mapID, err)
		return nil, grpc.Errorf(codes.Internal, "Fetching latest signed map root failed")
	}

	currentEpoch := resp.GetMapRoot().GetMapRevision()
	if err := validateListEntryHistoryRequest(in, currentEpoch); err != nil {
		glog.Errorf("validateListEntryHistoryRequest(%v, %v): %v", in, currentEpoch, err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// Get all GetEntryResponse for all epochs in the range [start, start +
	// in.PageSize].
	responses := make([]*pb.GetEntryResponse, in.PageSize)
	for i := range responses {
		resp, err := s.getEntry(ctx, in.UserId, in.AppId, in.FirstTreeSize, in.Start+int64(i))
		if err != nil {
			glog.Errorf("getEntry failed for epoch %v: %v", in.Start+int64(i), err)
			return nil, grpc.Errorf(codes.Internal, "GetEntry failed")
		}
		responses[i] = resp
	}

	nextStart := in.Start + int64(in.PageSize)
	if nextStart > currentEpoch {
		nextStart = 0
	}

	return &pb.ListEntryHistoryResponse{
		Values:    responses,
		NextStart: nextStart,
	}, nil
}

// UpdateEntry updates a user's profile. If the user does not exist, a new
// profile will be created.
func (s *Server) UpdateEntry(ctx context.Context, in *pb.UpdateEntryRequest) (*pb.UpdateEntryResponse, error) {
	// Validate proper authentication.
	sctx, err := s.auth.ValidateCreds(ctx)
	switch err {
	case nil:
		break // Authentication succeeded.
	case authentication.ErrMissingAuth:
		return nil, grpc.Errorf(codes.Unauthenticated, "Missing authentication header")
	default:
		glog.Warningf("Auth failed: %v", err)
		return nil, grpc.Errorf(codes.Unauthenticated, "Unauthenticated")
	}
	// Validate proper authorization.
	if s.authz.IsAuthorized(sctx, s.mapID, in.AppId, in.UserId, authzpb.Permission_WRITE) != nil {
		glog.Warningf("Authz failed: %v", err)
		return nil, grpc.Errorf(codes.PermissionDenied, "Unauthorized")
	}
	// Verify:
	// - Index to Key equality in SignedKV.
	// - Correct profile commitment.
	// - Correct key formats.
	if err := validateUpdateEntryRequest(in, s.vrf); err != nil {
		glog.Warningf("Invalid UpdateEntryRequest: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid request")
	}

	if err := s.saveCommitment(ctx, in.GetEntryUpdate().GetMutation(), in.GetEntryUpdate().Committed); err != nil {
		return nil, err
	}

	// Query for the current epoch.
	req := &pb.GetEntryRequest{
		UserId: in.UserId,
		AppId:  in.AppId,
		//EpochStart: in.GetEntryUpdate().EpochStart,
	}
	resp, err := s.GetEntry(ctx, req)
	if err != nil {
		glog.Errorf("GetEntry failed: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Read failed")
	}

	// Catch errors early. Perform mutation verification.
	// Read at the current value. Assert the following:
	// - Correct signatures from previous epoch.
	// - Correct signatures internal to the update.
	// - Hash of current data matches the expectation in the mutation.

	// The very first mutation will have resp.LeafProof.MapLeaf.LeafValue=nil.
	oldLeafB := resp.GetLeafProof().GetLeaf().GetLeafValue()
	oldEntry, err := entry.FromLeafValue(oldLeafB)
	if err != nil {
		glog.Errorf("entry.FromLeafValue: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "invalid previous leaf value")
	}
	if _, err := s.mutator.Mutate(oldEntry, in.GetEntryUpdate().GetMutation()); err == mutator.ErrReplay {
		glog.Warningf("Discarding request due to replay")
		// Return the response. The client should handle the replay case
		// by comparing the returned response with the request. Check
		// Retry() in client/client.go.
		return &pb.UpdateEntryResponse{Proof: resp}, nil
	} else if err != nil {
		glog.Warningf("Invalid mutation: %v", err)
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid mutation")
	}

	// Save mutation to the database.
	txn, err := s.factory.NewTxn(ctx)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot create transaction")
	}
	if _, err := s.mutations.Write(txn, in.GetEntryUpdate().GetMutation()); err != nil {
		glog.Errorf("mutations.Write failed: %v", err)
		if err := txn.Rollback(); err != nil {
			glog.Errorf("Cannot rollback the transaction: %v", err)
		}
		return nil, grpc.Errorf(codes.Internal, "Mutation write error")
	}
	if err := txn.Commit(); err != nil {
		glog.Errorf("Cannot commit transaction: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Cannot commit transaction")
	}
	return &pb.UpdateEntryResponse{Proof: resp}, nil
}

// GetDomainInfo returns all info tied to the specified domain.
//
// This API to get all necessary data needed to verify a particular
// key-server. Data contains for instance the tree-info, like for instance the
// log-/map-id and the corresponding public-keys.
func (s *Server) GetDomainInfo(ctx context.Context, in *pb.GetDomainInfoRequest) (*pb.GetDomainInfoResponse, error) {
	logTree, err := s.tadmin.GetTree(ctx, &trillian.GetTreeRequest{
		TreeId: s.logID,
	})
	if err != nil {
		return nil, err
	}
	mapTree, err := s.tadmin.GetTree(ctx, &trillian.GetTreeRequest{
		TreeId: s.mapID,
	})
	if err != nil {
		return nil, err
	}

	vrfPubKeyPB, err := der.ToPublicProto(s.vrf.Public())
	if err != nil {
		return nil, err
	}

	return &pb.GetDomainInfoResponse{
		Log: logTree,
		Map: mapTree,
		Vrf: vrfPubKeyPB,
	}, nil
}

func (s *Server) saveCommitment(ctx context.Context, entry *pb.SignedKV, committed *pb.Committed) error {
	// Write the commitment.
	if err := s.committer.Write(ctx, entry.Commitment, committed.Data, committed.Key); err != nil {
		glog.Errorf("committer.Write failed: %v", err)
		return grpc.Errorf(codes.Internal, "Write failed")
	}
	return nil
}
