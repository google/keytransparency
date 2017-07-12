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

// Package monitor implements the monitor service. A monitor repeatedly polls a
// key-transparency server's Mutations API and signs Map Roots if it could
// reconstruct
// clients can query.
package monitor

import (
	"time"

	"github.com/golang/glog"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/trillian"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	tv "github.com/google/keytransparency/core/tree/sparse/verifier"

	mspb "github.com/google/keytransparency/impl/proto/monitor_v1_service"
	mupb "github.com/google/keytransparency/impl/proto/mutation_v1_service"

	"bytes"
	"github.com/google/keytransparency/core/tree/sparse"
)

// Each page contains pageSize profiles. Each profile contains multiple
// keys. Assuming 2 keys per profile (each of size 2048-bit), a page of
// size 16 will contain about 8KB of data.
const pageSize = 16

// Server holds internal state for the monitor server.
type server struct {
	client     mupb.MutationServiceClient
	pollPeriod time.Duration

	tree *tv.Verifier
	// TODO(ismail) abstract this into a storage interface and have an in-memory version
	seenSMRs          []*trillian.SignedMapRoot
	reconstructedSMRs []*trillian.SignedMapRoot
}

// New creates a new instance of the monitor server.
func New(cli mupb.MutationServiceClient, mapID int64, poll time.Duration) *server {
	return &server{
		client:     cli,
		pollPeriod: poll,
		// TODO TestMapHasher (maphasher.Default) does not implement sparse.TreeHasher:
		tree:              tv.New(mapID, sparse.CONIKSHasher),
		seenSMRs:          make([]*trillian.SignedMapRoot, 256),
		reconstructedSMRs: make([]*trillian.SignedMapRoot, 256),
	}
}

func (s *server) StartPolling() error {
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

// GetSignedMapRoot returns the latest reconstructed using the Mutations API and
// validated signed map root.
func (s *server) GetSignedMapRoot(ctx context.Context, in *ktpb.GetMonitoringRequest) (*ktpb.GetMonitoringResponse, error) {
	return &ktpb.GetMonitoringResponse{
		Smr: s.lastSMR(),
	}, nil
}

// GetSignedMapRootStream is a streaming API similar to GetSignedMapRoot.
func (s *server) GetSignedMapRootStream(in *ktpb.GetMonitoringRequest, stream mspb.MonitorService_GetSignedMapRootStreamServer) error {
	// TODO(ismail): implement stream API
	return grpc.Errorf(codes.Unimplemented, "GetSignedMapRootStream is unimplemented")
}

func (s *server) GetSignedMapRootByRevision(ctx context.Context, in *ktpb.GetMonitoringRequest) (*ktpb.GetMonitoringResponse, error) {
	// TODO(ismail): implement by revision API
	return nil, grpc.Errorf(codes.Unimplemented, "GetSignedMapRoot is unimplemented")
}

func (s *server) pollMutations(ctx context.Context, opts ...grpc.CallOption) ([]*ktpb.Mutation, error) {
	req := &ktpb.GetMutationsRequest{PageSize: pageSize, Epoch: s.nextRevToQuery()}
	resp, err := s.client.GetMutations(ctx, req, opts...)
	if err != nil {
		return nil, err
	}

	// TODO(ismail): remember when we've actually requested and seen this SMR!
	// publish delta (seen - actual)
	if got, want := resp.GetSmr(), s.lastSeenSMR(); bytes.Equal(got.GetRootHash(), want.GetRootHash()) &&
		got.GetMapRevision() == want.GetMapRevision() {
		// We already processed this SMR. Do not update seen SMRs. Do not scroll
		// pages for further mutations. Return empty mutations list.
		glog.Infof("Already processed this SMR with revision %v. Continuing.", got.GetMapRevision())
		return nil, nil
	}

	mutations := make([]*ktpb.Mutation, pageSize*2)
	mutations = append(mutations, resp.GetMutations()...)
	s.pageMutations(ctx, resp, mutations, opts)

	// update seen SMRs:
	s.seenSMRs = append(s.seenSMRs, resp.GetSmr())

	// TODO(ismail):
	// For each received mutation in epoch e:
	// Verify that the provided leaf’s inclusion proof goes to epoch e -1.
	// Verify the mutation’s validity against the previous leaf.
	// Compute the new leaf and store the intermediate hashes locally.
	// Compute the new root using local intermediate hashes from epoch e.
	for _, m := range mutations {
		idx := m.GetProof().GetLeaf().GetIndex()
		nbrs := m.GetProof().GetInclusion()
		if err := s.tree.VerifyProof(nbrs, idx, m.GetProof().GetLeaf().GetLeafValue(),
			sparse.FromBytes(resp.GetSmr().GetRootHash())); err != nil {
			glog.Errorf("VerifyProof(): %v", err)
			// TODO return nil, err
		}
	}

	// TODO(ismail): sign and update reconstructedSMRs
	// here we just add the kt-server signed SMR:
	glog.Errorf("Got reponse: %v", resp.GetSmr())
	s.reconstructedSMRs = append(s.reconstructedSMRs, resp.GetSmr())

	return mutations, nil
}

// pageMutations iterates/pages through all mutations in the case there were
// more then maximum pageSize mutations in between epochs.
// It will modify the passed GetMutationsResponse resp and the passed list of
// mutations ms.
func (s *server) pageMutations(ctx context.Context, resp *ktpb.GetMutationsResponse,
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

func (s *server) lastSeenSMR() *trillian.SignedMapRoot {
	if len(s.seenSMRs) > 0 {
		return s.seenSMRs[len(s.seenSMRs)-1]
	}
	return nil
}

func (s *server) lastSMR() *trillian.SignedMapRoot {
	if len(s.reconstructedSMRs) > 0 {
		return s.reconstructedSMRs[len(s.reconstructedSMRs)-1]
	}
	return nil
}

func (s *server) nextRevToQuery() int64 {
	smr := s.lastSeenSMR()
	if smr == nil {
		return 1
	}
	return smr.GetMapRevision() + 1
}
