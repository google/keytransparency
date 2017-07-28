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

// Package monitor implements the monitor service. A monitor repeatedly polls a
// key-transparency server's Mutations API and signs Map Roots if it could
// reconstruct
// clients can query.
package monitor

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	tv "github.com/google/keytransparency/core/tree/sparse/verifier"

	mspb "github.com/google/keytransparency/impl/proto/monitor_v1_service"
	mupb "github.com/google/keytransparency/impl/proto/mutation_v1_service"

	"github.com/google/keytransparency/core/tree/sparse"
)

// Each page contains pageSize profiles. Each profile contains multiple
// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
// size 16 will contain about 8KB of data.
const pageSize = 16

var (
	// ErrInvalidMutation occurs when verification failed because of an invalid
	// mutation.
	ErrInvalidMutation = errors.New("Invalid mutation")
	// ErrNotMatchingRoot occurs when the reconstructed root differs from the one
	// we received from the server.
	ErrNotMatchingRoot = errors.New("Recreated root does not match")
	// ErrInvalidSignature occurs when the signature on the observed map root is
	// invalid.
	ErrInvalidSignature = errors.New("Recreated root does not match")
	// ErrNothingProcessed occurs when the monitor did not process any mutations /
	// smrs yet.
	ErrNothingProcessed = errors.New("did not process any mutations yet")
)

// Server holds internal state for the monitor server.
type Server struct {
	client     mupb.MutationServiceClient
	pollPeriod time.Duration

	tree           *tv.Verifier
	signer         crypto.Signer
	proccessedSMRs []*ktpb.GetMonitoringResponse
}

// New creates a new instance of the monitor server.
func New(cli mupb.MutationServiceClient, signer crypto.Signer, mapID int64, poll time.Duration) *Server {
	return &Server{
		client:     cli,
		pollPeriod: poll,
		// TODO TestMapHasher (maphasher.Default) does not implement sparse.TreeHasher:
		tree:           tv.New(mapID, sparse.CONIKSHasher),
		signer:         signer,
		proccessedSMRs: make([]*ktpb.GetMonitoringResponse, 256),
	}
}

// StartPolling initiates polling and processing mutations every pollPeriod.
func (s *Server) StartPolling() error {
	t := time.NewTicker(s.pollPeriod)
	for now := range t.C {
		glog.Infof("Polling: %v", now)
		ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
		if _, err := s.pollMutations(ctx); err != nil {
			glog.Errorf("pollMutations(_): %v", err)
		}
	}
	return nil
}

// GetSignedMapRoot returns the latest valid signed map root the monitor
// observed. Additionally, the response contains additional data necessary to
// reproduce errors on failure.
//
// Returns the signed map root for the latest epoch the monitor observed. If
// the monitor could not reconstruct the map root given the set of mutations
// from the previous to the current epoch it won't sign the map root and
// additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRoot(ctx context.Context, in *ktpb.GetMonitoringRequest) (*ktpb.GetMonitoringResponse, error) {
	if len(s.proccessedSMRs) > 0 {
		return s.proccessedSMRs[len(s.proccessedSMRs)-1], nil
	}
	return nil, ErrNothingProcessed
}

// GetSignedMapRootStream is a streaming API similar to GetSignedMapRoot.
func (s *Server) GetSignedMapRootStream(in *ktpb.GetMonitoringRequest, stream mspb.MonitorService_GetSignedMapRootStreamServer) error {
	// TODO(ismail): implement stream API
	return grpc.Errorf(codes.Unimplemented, "GetSignedMapRootStream is unimplemented")
}

// GetSignedMapRootByRevision works similar to GetSignedMapRoot but returns
// the monitor's result for a specific map revision.
//
// Returns the signed map root for the specified epoch the monitor observed.
// If the monitor could not reconstruct the map root given the set of
// mutations from the previous to the current epoch it won't sign the map root
// and additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRootByRevision(ctx context.Context, in *ktpb.GetMonitoringRequest) (*ktpb.GetMonitoringResponse, error) {
	// TODO(ismail): implement by revision API
	return nil, grpc.Errorf(codes.Unimplemented, "GetSignedMapRoot is unimplemented")
}

func (s *Server) pollMutations(ctx context.Context, opts ...grpc.CallOption) ([]*ktpb.Mutation, error) {
	req := &ktpb.GetMutationsRequest{PageSize: pageSize, Epoch: s.nextRevToQuery()}
	resp, err := s.client.GetMutations(ctx, req, opts...)
	if err != nil {
		return nil, err
	}

	seen := time.Now().UnixNano()
	if got, want := resp.GetSmr(), s.lastSeenSMR(); bytes.Equal(got.GetRootHash(), want.GetRootHash()) &&
		got.GetMapRevision() == want.GetMapRevision() {
		// We already processed this SMR. Do not update seen SMRs. Do not scroll
		// pages for further mutations. Return empty mutations list.
		glog.Infof("Already processed this SMR with revision %v. Continuing.", got.GetMapRevision())
		return nil, nil
	}

	mutations := make([]*ktpb.Mutation, pageSize*2)
	mutations = append(mutations, resp.GetMutations()...)
	if err := s.pageMutations(ctx, resp, mutations, opts...); err != nil {
		glog.Errorf("s.pageMutations(_): %v", err)
		return nil, err
	}

	// update seen SMRs:
	// TODO: this should be

	rh := resp.GetSmr().GetRootHash()
	switch err := s.verifyMutations(mutations, rh); err {
	// TODO(ismail): return proper data for failure cases:
	case ErrInvalidMutation:
		glog.Errorf("TODO: handle this ErrInvalidMutation properly")
	case ErrInvalidSignature:
		glog.Errorf("TODO: handle this ErrInvalidSignature properly (return SMR)")
	case ErrNotMatchingRoot:
		glog.Errorf("TODO: handle this ErrNotMatchingRoot properly")
	case nil:
		glog.Info("TODO: Successfully verified.")
	default:
		glog.Errorf("Unexpected error: %v", err)
	}

	// TODO(ismail): Sign reconstructed Hash instead of response hash:
	sig, err := s.signer.SignObject(resp.GetSmr().GetRootHash())
	if err != nil {
		return nil, fmt.Errorf("s.signer.SignObject(_): %v", err)
	}
	// Update seen/processed signed map roots:
	s.proccessedSMRs = append(s.proccessedSMRs,
		&ktpb.GetMonitoringResponse{
			Smr: &trillian.SignedMapRoot{
				Signature:      sig,
				TimestampNanos: resp.GetSmr().GetTimestampNanos(),
				RootHash:       resp.GetSmr().GetRootHash(),
				Metadata:       resp.GetSmr().GetMetadata(),
				MapId:          resp.GetSmr().GetMapId(),
				MapRevision:    resp.GetSmr().GetMapRevision(),
			},
			IsValid:            true,
			SeenTimestampNanos: seen,
		})

	return mutations, nil
}

func (s *Server) verifyMutations(ms []*ktpb.Mutation, expectedRoot []byte) error {
	// TODO(ismail):
	// For each received mutation in epoch e:
	// Verify that the provided leaf’s inclusion proof goes to epoch e -1.
	// Verify the mutation’s validity against the previous leaf.
	// Compute the new leaf and store the intermediate hashes locally.
	// Compute the new root using local intermediate hashes from epoch e.
	for _, m := range ms {
		idx := m.GetProof().GetLeaf().GetIndex()
		nbrs := m.GetProof().GetInclusion()
		if err := s.tree.VerifyProof(nbrs, idx, m.GetProof().GetLeaf().GetLeafValue(),
			sparse.FromBytes(expectedRoot)); err != nil {
			glog.Errorf("VerifyProof(): %v", err)
			// TODO return nil, err
		}
	}

	return nil
}

// pageMutations iterates/pages through all mutations in the case there were
// more then maximum pageSize mutations in between epochs.
// It will modify the passed GetMutationsResponse resp and the passed list of
// mutations ms.
func (s *Server) pageMutations(ctx context.Context, resp *ktpb.GetMutationsResponse,
	ms []*ktpb.Mutation, opts ...grpc.CallOption) error {
	// Query all mutations in the current epoch
	for resp.GetNextPageToken() != "" {
		req := &ktpb.GetMutationsRequest{PageSize: pageSize}
		resp, err := s.client.GetMutations(ctx, req, opts...)
		if err != nil {
			return err
		}
		ms = append(ms, resp.GetMutations()...)
	}
	return nil
}

func (s *Server) lastSeenSMR() *trillian.SignedMapRoot {
	if len(s.proccessedSMRs) > 0 {
		return s.proccessedSMRs[len(s.proccessedSMRs)-1].GetSmr()
	}
	return nil
}

func (s *Server) nextRevToQuery() int64 {
	smr := s.lastSeenSMR()
	if smr == nil {
		return 1
	}
	return smr.GetMapRevision() + 1
}
