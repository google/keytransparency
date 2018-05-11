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
	"database/sql"

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/authorization"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authzpb "github.com/google/keytransparency/core/api/type/type_go_proto"
	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// Server holds internal state for the key server.
type Server struct {
	tlog      tpb.TrillianLogClient
	tmap      tpb.TrillianMapClient
	logAdmin  tpb.TrillianAdminClient
	mapAdmin  tpb.TrillianAdminClient
	auth      authentication.Authenticator
	authz     authorization.Authorization
	mutator   mutator.Func
	domains   domain.Storage
	queue     mutator.MutationQueue
	mutations mutator.MutationStorage
	indexFunc indexFunc
}

// New creates a new instance of the key server.
func New(tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	logAdmin tpb.TrillianAdminClient,
	mapAdmin tpb.TrillianAdminClient,
	mutator mutator.Func,
	auth authentication.Authenticator,
	authz authorization.Authorization,
	domains domain.Storage,
	queue mutator.MutationQueue,
	mutations mutator.MutationStorage) *Server {
	return &Server{
		tlog:      tlog,
		tmap:      tmap,
		logAdmin:  logAdmin,
		mapAdmin:  mapAdmin,
		mutator:   mutator,
		auth:      auth,
		authz:     authz,
		domains:   domains,
		queue:     queue,
		mutations: mutations,
		indexFunc: indexFromVRF,
	}
}

// GetEntry returns a user's profile and proof that there is only one object for
// this user and that it is the same one being provided to everyone else.
// GetEntry also supports querying past values by setting the epoch field.
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.GetEntryResponse, error) {
	domainID := in.GetDomainId()
	if domainID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a domain_id")
	}

	// Lookup log and map info.
	d, err := s.domains.Read(ctx, domainID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", domainID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	// Fetch latest revision.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, in.GetFirstTreeSize())
	if err != nil {
		return nil, err
	}
	revision, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("latestRevision(log %v, sth%v): %v", d.LogID, sth, err)
		return nil, err
	}

	entryProof, err := s.getEntryByRevision(ctx, sth, d, in.UserId, in.AppId, revision)
	if err != nil {
		return nil, err
	}
	resp := &pb.GetEntryResponse{
		LogRoot:        sth,
		LogConsistency: consistencyProof.GetHashes(),
	}
	proto.Merge(resp, entryProof)
	return resp, nil
}

// getEntryByRevision returns an entry and its proofs.
// getEntryByRevision does NOT populate the following fields:
// - LogRoot
// - LogConsistency
func (s *Server) getEntryByRevision(ctx context.Context, sth *tpb.SignedLogRoot, d *domain.Domain, userID, appID string, mapRevision int64) (*pb.GetEntryResponse, error) {
	if mapRevision < 0 {
		return nil, status.Errorf(codes.InvalidArgument,
			"Revision is %v, want >= 0", mapRevision)
	}

	index, proof, err := s.indexFunc(ctx, d, appID, userID)
	if err != nil {
		return nil, err
	}

	getResp, err := s.tmap.GetLeavesByRevision(ctx, &tpb.GetMapLeavesByRevisionRequest{
		MapId:    d.MapID,
		Index:    [][]byte{index[:]},
		Revision: mapRevision,
	})
	if err != nil {
		glog.Errorf("GetLeavesByRevision(%v, rev: %v): %v", d.MapID, mapRevision, err)
		return nil, status.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	if got, want := len(getResp.MapLeafInclusion), 1; got != want {
		glog.Errorf("GetLeavesByRevision() len: %v, want %v", got, want)
		return nil, status.Errorf(codes.Internal, "Failed fetching map leaf")
	}
	neighbors := getResp.MapLeafInclusion[0].GetInclusion()
	leaf := getResp.MapLeafInclusion[0].GetLeaf().GetLeafValue()
	extraData := getResp.MapLeafInclusion[0].GetLeaf().GetExtraData()

	var committed *pb.Committed
	if leaf != nil {
		if extraData == nil {
			return nil, status.Errorf(codes.Internal, "Missing commitment data")
		}
		committed = &pb.Committed{}
		if err := proto.Unmarshal(extraData, committed); err != nil {
			return nil, status.Errorf(codes.Internal, "Cannot read committed value")
		}
	}

	// SignedMapHead to SignedLogRoot inclusion proof.
	secondTreeSize := sth.GetTreeSize()
	logInclusion, err := s.tlog.GetInclusionProof(ctx,
		&tpb.GetInclusionProofRequest{
			LogId: d.LogID,
			// SignedMapRoot must be placed in the log at MapRevision.
			// MapRevisions start at 0. Log leaves start at 0.
			LeafIndex: mapRevision,
			TreeSize:  secondTreeSize,
		})
	if err != nil {
		glog.Errorf("tlog.GetInclusionProof(%v, %v, %v): %v", d.LogID, mapRevision, secondTreeSize, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch log inclusion proof")
	}

	return &pb.GetEntryResponse{
		VrfProof:  proof,
		Committed: committed,
		LeafProof: &tpb.MapLeafInclusion{
			Inclusion: neighbors,
			Leaf: &tpb.MapLeaf{
				LeafValue: leaf,
			},
		},
		Smr:          getResp.GetMapRoot(),
		LogInclusion: logInclusion.GetProof().GetHashes(),
	}, nil
}

// ListEntryHistory returns a list of EntryProofs covering a period of time.
func (s *Server) ListEntryHistory(ctx context.Context, in *pb.ListEntryHistoryRequest) (*pb.ListEntryHistoryResponse, error) {
	// Lookup log and map info.
	domainID := in.GetDomainId()
	if domainID == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a domain_id")
	}
	d, err := s.domains.Read(ctx, domainID, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", domainID, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}

	// Fetch latest revision.
	sth, consistencyProof, err := s.latestLogRootProof(ctx, d, in.GetFirstTreeSize())
	if err != nil {
		return nil, err
	}
	currentEpoch, err := mapRevisionFor(sth)
	if err != nil {
		glog.Errorf("latestRevision(log %v, sth%v): %v", d.LogID, sth, err)
		return nil, err
	}

	if err := validateListEntryHistoryRequest(in, currentEpoch); err != nil {
		glog.Errorf("validateListEntryHistoryRequest(%v, %v): %v", in, currentEpoch, err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// TODO(gbelvin): fetch all history from trillian at once.
	// Get all GetEntryResponse for all epochs in the range [start, start + in.PageSize].
	responses := make([]*pb.GetEntryResponse, in.PageSize)
	for i := range responses {
		resp, err := s.getEntryByRevision(ctx, sth, d, in.UserId, in.AppId, in.Start+int64(i))
		if err != nil {
			glog.Errorf("getEntry failed for epoch %v: %v", in.Start+int64(i), err)
			return nil, status.Errorf(codes.Internal, "GetEntry failed")
		}
		proto.Merge(resp, &pb.GetEntryResponse{
			LogRoot: sth,
			// TODO(gbelvin): This is redundant and wasteful. Refactor response API.
			LogConsistency: consistencyProof.GetHashes(),
		})
		responses[i] = resp
	}

	nextStart := in.Start + int64(len(responses))
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
	if in.DomainId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a domain_id")
	}
	// Lookup log and map info.
	domain, err := s.domains.Read(ctx, in.DomainId, false)
	if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info")
	}
	vrfPriv, err := p256.NewFromWrappedKey(ctx, domain.VRFPriv)
	if err != nil {
		return nil, err
	}

	// Validate proper authentication.
	sctx, err := s.auth.ValidateCreds(ctx)
	switch err {
	case nil:
		break // Authentication succeeded.
	case authentication.ErrMissingAuth:
		return nil, status.Errorf(codes.Unauthenticated, "Missing authentication header")
	default:
		glog.Warningf("Auth failed: %v", err)
		return nil, status.Errorf(codes.Unauthenticated, "Unauthenticated")
	}
	// Validate proper authorization.
	if s.authz.IsAuthorized(sctx, domain.DomainID, in.AppId, in.UserId, authzpb.Permission_WRITE) != nil {
		glog.Warningf("Authz failed: %v", err)
		return nil, status.Errorf(codes.PermissionDenied, "Unauthorized")
	}
	// Verify:
	// - Index to Key equality in SignedKV.
	// - Correct profile commitment.
	// - Correct key formats.
	if err := validateUpdateEntryRequest(in, vrfPriv); err != nil {
		glog.Warningf("Invalid UpdateEntryRequest: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid request")
	}

	// Query for the current epoch.
	req := &pb.GetEntryRequest{
		DomainId: in.DomainId,
		UserId:   in.UserId,
		AppId:    in.AppId,
		//EpochStart: in.GetEntryUpdate().EpochStart,
	}
	resp, err := s.GetEntry(ctx, req)
	if err != nil {
		glog.Errorf("GetEntry failed: %v", err)
		return nil, status.Errorf(codes.Internal, "Read failed")
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
		return nil, status.Errorf(codes.InvalidArgument, "invalid previous leaf value")
	}
	if _, err := s.mutator.Mutate(oldEntry, in.GetEntryUpdate().GetMutation()); err == mutator.ErrReplay {
		glog.Warningf("Discarding request due to replay")
		// Return the response. The client should handle the replay case
		// by comparing the returned response with the request. Check
		// Retry() in client/client.go.
		return &pb.UpdateEntryResponse{Proof: resp}, nil
	} else if err != nil {
		glog.Warningf("Invalid mutation: %v", err)
		return nil, status.Errorf(codes.InvalidArgument, "Invalid mutation")
	}

	// Save mutation to the database.
	if err := s.queue.Send(ctx, domain.DomainID, in.GetEntryUpdate()); err != nil {
		glog.Errorf("mutations.Write failed: %v", err)
		return nil, status.Errorf(codes.Internal, "Mutation write error")
	}
	return &pb.UpdateEntryResponse{Proof: resp}, nil
}

// GetDomain returns all info tied to the specified domain.
//
// This API to get all necessary data needed to verify a particular
// key-server. Data contains for instance the tree-info, like for instance the
// log/map-id and the corresponding public-keys.
func (s *Server) GetDomain(ctx context.Context, in *pb.GetDomainRequest) (*pb.Domain, error) {
	// Lookup log and map info.
	if in.DomainId == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Please specify a domain_id")
	}
	domain, err := s.domains.Read(ctx, in.DomainId, false)
	if err == sql.ErrNoRows {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.NotFound, "Domain %v not found", in.DomainId)
	} else if err != nil {
		glog.Errorf("adminstorage.Read(%v): %v", in.DomainId, err)
		return nil, status.Errorf(codes.Internal, "Cannot fetch domain info for %v", in.DomainId)
	}

	logTree, err := s.logAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: domain.LogID})
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Cannot fetch log info for %v: %v", in.DomainId, err)
	}
	mapTree, err := s.mapAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: domain.MapID})
	if err != nil {
		return nil, status.Errorf(codes.Internal,
			"Cannot fetch map info for %v: %v", in.DomainId, err)
	}

	return &pb.Domain{
		DomainId:    domain.DomainID,
		Log:         logTree,
		Map:         mapTree,
		Vrf:         domain.VRF,
		MinInterval: ptypes.DurationProto(domain.MinInterval),
		MaxInterval: ptypes.DurationProto(domain.MaxInterval),
	}, nil
}

// indexFunc computes an index and proof for domain/app/user
type indexFunc func(ctx context.Context, d *domain.Domain, appID, userID string) ([32]byte, []byte, error)

// index returns the index and proof for domain/app/user
func indexFromVRF(ctx context.Context, d *domain.Domain, appID, userID string) ([32]byte, []byte, error) {
	vrfPriv, err := p256.NewFromWrappedKey(ctx, d.VRFPriv)
	if err != nil {
		return [32]byte{}, nil, err
	}
	index, proof := vrfPriv.Evaluate(vrf.UniqueID(userID, appID))
	return index, proof, nil
}
