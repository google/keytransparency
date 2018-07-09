// Copyright 2018 Google Inc. All Rights Reserved.
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

package sequencer

import (
	"context"
	"sync"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/glog"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

const (
	domainIDLabel = "domainid"
	reasonLabel   = "reason"
)

var (
	once             sync.Once
	knownDomains     monitoring.Gauge
	batchSize        monitoring.Gauge
	mutationCount    monitoring.Counter
	mutationFailures monitoring.Counter
)

func createMetrics(mf monitoring.MetricFactory) {
	knownDomains = mf.NewGauge(
		"known_domains",
		"Set to 1 for known domains (whether this instance is master or not)",
		domainIDLabel)
	mutationCount = mf.NewCounter(
		"mutation_count",
		"Number of mutations the signer has processed for domainid since process start",
		domainIDLabel)
	mutationFailures = mf.NewCounter(
		"mutation_failures",
		"Number of invalid mutations the signer has processed for domainid since process start",
		domainIDLabel, reasonLabel)
	batchSize = mf.NewGauge(
		"batch_size",
		"Number of mutations the signer is attempting to process for domainid",
		domainIDLabel)
}

// Server implements KeyTransparencySequencerServer.
type Server struct {
	ktServer  *keyserver.Server
	mutations mutator.MutationStorage
	tmap      tpb.TrillianMapClient
	tlog      tpb.TrillianLogClient
}

// NewServer creates a new KeyTransparencySequencerServer.
func NewServer(
	domains domain.Storage,
	logAdmin tpb.TrillianAdminClient,
	mapAdmin tpb.TrillianAdminClient,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	mutations mutator.MutationStorage,
	metricsFactory monitoring.MetricFactory,
) *Server {
	once.Do(func() { createMetrics(metricsFactory) })
	return &Server{
		ktServer:  keyserver.New(nil, nil, logAdmin, mapAdmin, nil, domains, nil, nil),
		tlog:      tlog,
		tmap:      tmap,
		mutations: mutations,
	}
}

// CreateEpoch applies the supplied mutations to the current map revision and creates a new epoch.
func (s *Server) CreateEpoch(ctx context.Context, in *spb.CreateEpochRequest) (*empty.Empty, error) {
	domainID := in.GetDomainId()
	msgs := in.GetMessages()
	glog.Infof("CreateEpoch: for %v with %d messages", domainID, len(msgs))
	// Fetch verification objects for domainID.
	config, err := s.ktServer.GetDomain(ctx, &ktpb.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, err
	}
	cli, err := client.NewVerifierFromDomain(config)
	if err != nil {
		return nil, err
	}

	// Parse mutations using the mutator for this domain.
	batchSize.Set(float64(len(msgs)), config.DomainId)
	indexes := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		indexes = append(indexes, m.GetMutation().GetIndex())
	}
	glog.V(2).Infof("CreateEpoch: %v mutations, %v indexes", len(msgs), len(indexes))

	mapRoot, err := s.getAndVerifyMapRoot(ctx, cli, config.Map.TreeId)
	if err != nil {
		return nil, err
	}
	glog.V(3).Infof("CreateEpoch: Previous SignedMapRoot: {Revision: %v}", mapRoot.Revision)

	leaves, err := s.getAndVerifyMapLeaves(ctx, cli.MapVerifier, mapRoot, config.Map.TreeId, indexes)
	if err != nil {
		return nil, err
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(domainID, entry.New(), in.GetMessages(), leaves)
	if err != nil {
		return nil, err
	}

	// Set new leaf values.
	setResp, err := s.tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		MapId:  config.Map.TreeId,
		Leaves: newLeaves,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmap.SetLeaves(): %v", err)
	}
	mapRoot, err = cli.VerifySignedMapRoot(setResp.GetMapRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	glog.V(2).Infof("CreateEpoch: SetLeaves:{Revision: %v}", mapRoot.Revision)

	// Write mutations associated with this epoch.
	mutations := make([]*ktpb.Entry, 0, len(msgs))
	for _, msg := range msgs {
		mutations = append(mutations, msg.Mutation)
	}
	if err := s.mutations.WriteBatch(ctx, domainID, int64(mapRoot.Revision), mutations); err != nil {
		glog.Errorf("Could not write mutations for revision %v: %v", mapRoot.Revision, err)
		return nil, status.Errorf(codes.Internal, "mutations.WriteBatch(): %v", err)
	}

	// TODO(gbelvin): Store and track trustedRoot.
	trustedRoot := types.LogRootV1{} // Automatically trust the first observed log root.

	// Put SignedMapHead in the append only log.
	logClient, err := tclient.NewFromTree(s.tlog, config.Log, trustedRoot)
	if err != nil {
		return nil, err
	}
	if err := logClient.AddSequencedLeafAndWait(ctx, setResp.GetMapRoot().GetMapRoot(), int64(mapRoot.Revision)); err != nil {
		glog.Fatalf("AddSequencedLeaf(logID: %v, rev: %v): %v", config.Log.TreeId, mapRoot.Revision, err)
		// TODO(gdbelvin): Implement retries.
		return nil, err
	}

	mutationCount.Add(float64(len(msgs)), domainID)
	glog.Infof("CreatedEpoch: rev: %v with %v mutations, root: %x", mapRoot.Revision, len(msgs), mapRoot.RootHash)
	return nil, nil
}

// applyMutations takes the set of mutations and applies them to given leafs.
// Multiple mutations for the same leaf will be applied to provided leaf.
// The last valid mutation for each leaf is included in the output.
// Returns a list of map leaves that should be updated.
func (s *Server) applyMutations(domainID string, mutatorFunc mutator.Func,
	msgs []*ktpb.EntryUpdate, leaves []*tpb.MapLeaf) ([]*tpb.MapLeaf, error) {
	// Put leaves in a map from index to leaf value.
	leafMap := make(map[string]*tpb.MapLeaf)
	for _, l := range leaves {
		leafMap[string(l.Index)] = l
	}

	retMap := make(map[string]*tpb.MapLeaf)
	for _, msg := range msgs {
		index := msg.Mutation.GetIndex()
		var oldValue *ktpb.Entry // If no map leaf was found, oldValue will be nil.
		if leaf, ok := leafMap[string(index)]; ok {
			var err error
			oldValue, err = entry.FromLeafValue(leaf.GetLeafValue())
			if err != nil {
				glog.Warningf("entry.FromLeafValue(%v): %v", leaf.GetLeafValue(), err)
				mutationFailures.Inc(domainID, "Unmarshal")
				continue
			}
		}

		newValue, err := mutatorFunc.Mutate(oldValue, msg.Mutation)
		if err != nil {
			glog.Warningf("Mutate(): %v", err)
			mutationFailures.Inc(domainID, "Mutate")
			continue // A bad mutation should not make the whole batch fail.
		}
		leafValue, err := entry.ToLeafValue(newValue)
		if err != nil {
			glog.Warningf("ToLeafValue(): %v", err)
			mutationFailures.Inc(domainID, "Marshal")
			continue
		}
		extraData, err := proto.Marshal(msg.Committed)
		if err != nil {
			glog.Warningf("proto.Marshal(): %v", err)
			mutationFailures.Inc(domainID, "Marshal")
			continue
		}

		// Make sure that only ONE MapLeaf is output per index.
		retMap[string(index)] = &tpb.MapLeaf{
			Index:     index,
			LeafValue: leafValue,
			ExtraData: extraData,
		}
	}
	// Convert return map back into a list.
	ret := make([]*tpb.MapLeaf, 0, len(retMap))
	for _, v := range retMap {
		ret = append(ret, v)
	}
	glog.V(2).Infof("applyMutations applied %v mutations to %v leaves", len(msgs), len(leaves))
	return ret, nil
}

func (s *Server) getAndVerifyMapRoot(ctx context.Context, cli client.Verifier, mapID int64) (*types.MapRootV1, error) {
	rootResp, err := s.tmap.GetSignedMapRoot(ctx, &tpb.GetSignedMapRootRequest{MapId: mapID})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetSignedMapRoot(%v): %v", mapID, err)
	}
	mapRoot, err := cli.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	return mapRoot, nil
}

func (s *Server) getAndVerifyMapLeaves(ctx context.Context, verifier *tclient.MapVerifier, mapRoot *types.MapRootV1, mapID int64, indexes [][]byte) ([]*tpb.MapLeaf, error) {
	getResp, err := s.tmap.GetLeaves(ctx, &tpb.GetMapLeavesRequest{
		MapId: mapID,
		Index: indexes,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmap.GetLeaves(): %v", err)
	}
	if got, want := len(getResp.MapLeafInclusion), len(indexes); got != want {
		return nil, status.Errorf(codes.Internal, "got %v leaves, want %v", got, want)
	}
	leaves := make([]*tpb.MapLeaf, 0, len(getResp.MapLeafInclusion))
	for _, m := range getResp.MapLeafInclusion {
		if err := verifier.VerifyMapLeafInclusionHash(mapRoot.RootHash, m); err != nil {
			return nil, status.Errorf(codes.Internal, "map: VerifyMapLeafInclusion(): %v", err)
		}
		leaves = append(leaves, m.Leaf)
	}
	return leaves, nil
}
