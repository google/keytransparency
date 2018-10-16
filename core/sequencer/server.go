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

// LogsReader reads messages in multiple logs.
type LogsReader interface {
	// HighWatermarks returns the highest primary key for each log in the mutations table.
	HighWatermarks(ctx context.Context, domainID string) (map[int64]int64, error)
	// ReadLog returns the messages in the (low, high] range stored in the specified log.
	// ReadLog does NOT delete messages.
	ReadLog(ctx context.Context, domainID string, logID, low, high int64) ([]*mutator.LogMessage, error)
}

// Batcher writes batch definitions to storage.
type Batcher interface {
	// WriteBatchSources saves the (low, high] boundaries used for each log in making this revision.
	WriteBatchSources(ctx context.Context, domainID string, revision int64, sources map[int64]*spb.MapMetadata_SourceSlice) error
	// ReadBatch returns the batch definitions for a given revision.
	ReadBatch(ctx context.Context, domainID string, revision int64) (map[int64]*spb.MapMetadata_SourceSlice, error)
}

// Server implements KeyTransparencySequencerServer.
type Server struct {
	ktServer  *keyserver.Server
	batcher   Batcher
	mutations mutator.MutationStorage
	tmap      tpb.TrillianMapClient
	tlog      tpb.TrillianLogClient
	logs      LogsReader
}

// NewServer creates a new KeyTransparencySequencerServer.
func NewServer(
	domains domain.Storage,
	logAdmin tpb.TrillianAdminClient,
	mapAdmin tpb.TrillianAdminClient,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	batcher Batcher,
	mutations mutator.MutationStorage,
	logs LogsReader,
	metricsFactory monitoring.MetricFactory,
) *Server {
	once.Do(func() { createMetrics(metricsFactory) })
	return &Server{
		ktServer:  keyserver.New(nil, nil, logAdmin, mapAdmin, nil, domains, nil, nil),
		tlog:      tlog,
		tmap:      tmap,
		mutations: mutations,
		batcher:   batcher,
		logs:      logs,
	}
}

// RunBatch runs the full sequence of steps (for one domain) nessesary to get a
// mutation from the log integrated into the map. This consists of a series of
// idempotent steps:
// a) assign a batch of mutations from the logs to a map revision
// b) apply the batch to the map
// c) publish existing map roots to a log of SignedMapRoots.
func (s *Server) RunBatch(ctx context.Context, in *spb.RunBatchRequest) (*empty.Empty, error) {
	// Get the previous and current high water marks.
	domain, err := s.ktServer.GetDomain(ctx, &ktpb.GetDomainRequest{DomainId: in.DomainId})
	if err != nil {
		return nil, err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, domain.Map)
	if err != nil {
		return nil, err
	}
	latestMapRoot, err := mapClient.GetAndVerifyLatestMapRoot(ctx)
	if err != nil {
		return nil, err
	}
	var lastMeta spb.MapMetadata
	if err := proto.Unmarshal(latestMapRoot.Metadata, &lastMeta); err != nil {
		return nil, err
	}
	highs, err := s.logs.HighWatermarks(ctx, in.DomainId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "HighWatermark(): %v", err)
	}

	// TODO(#1057): If time since last map revision > max timeout, run batch.
	// TODO(#1047): If time since oldest log item > max latency has elapsed, run batch.
	// TODO(#1056): If count items > max_batch, run batch.

	// Count items to be processed.  Unfortunately, this means we will be
	// reading the items to be processed twice.  Once, here in RunBatch and
	// again in CreateEpoch.
	sources := make(map[int64]*spb.MapMetadata_SourceSlice)
	for sliceID, high := range highs {
		sources[sliceID] = &spb.MapMetadata_SourceSlice{
			LowestWatermark:  lastMeta.Sources[sliceID].GetHighestWatermark(),
			HighestWatermark: high,
		}
	}

	msgs, err := s.readMessages(ctx, in.DomainId, sources)
	if err != nil {
		return nil, err
	}
	if len(msgs) < int(in.MinBatch) {
		return &empty.Empty{}, nil
	}

	if err := s.batcher.WriteBatchSources(ctx, in.DomainId, int64(latestMapRoot.Revision)+1, sources); err != nil {
		return nil, err
	}

	return s.CreateEpoch(ctx, &spb.CreateEpochRequest{
		DomainId: in.DomainId,
		Revision: int64(latestMapRoot.Revision) + 1,
	})
}

func (s *Server) readMessages(ctx context.Context, domainID string,
	sources map[int64]*spb.MapMetadata_SourceSlice) ([]*ktpb.EntryUpdate, error) {
	msgs := make([]*ktpb.EntryUpdate, 0)
	for logID, source := range sources {
		batch, err := s.logs.ReadLog(ctx, domainID, logID,
			source.GetLowestWatermark(), source.GetHighestWatermark())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "ReadQueue(): %v", err)
		}
		for _, m := range batch {
			msgs = append(msgs, &ktpb.EntryUpdate{
				Mutation:  m.Mutation,
				Committed: m.ExtraData,
			})
		}
	}
	return msgs, nil
}

// CreateEpoch applies the supplied mutations to the current map revision and creates a new epoch.
func (s *Server) CreateEpoch(ctx context.Context, in *spb.CreateEpochRequest) (*empty.Empty, error) {
	domainID := in.GetDomainId()
	sources, err := s.batcher.ReadBatch(ctx, in.DomainId, in.Revision)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ReadBatch(%v, %v): %v", in.DomainId, in.Revision, err)
	}
	msgs, err := s.readMessages(ctx, in.DomainId, sources)
	if err != nil {
		return nil, err
	}
	glog.Infof("CreateEpoch: for %v with %d messages", domainID, len(msgs))
	// Fetch verification objects for domainID.
	config, err := s.ktServer.GetDomain(ctx, &ktpb.GetDomainRequest{DomainId: domainID})
	if err != nil {
		return nil, err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, config.Map)
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

	leaves, err := mapClient.GetAndVerifyMapLeaves(ctx, indexes)
	if err != nil {
		return nil, err
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(domainID, entry.New(), msgs, leaves)
	if err != nil {
		return nil, err
	}

	// Serialize metadata
	metadata, err := proto.Marshal(&spb.MapMetadata{Sources: sources})
	if err != nil {
		return nil, err
	}

	// Set new leaf values.
	setResp, err := s.tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		MapId:    config.Map.TreeId,
		Leaves:   newLeaves,
		Metadata: metadata,
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "tmap.SetLeaves(): %v", err)
	}
	mapRoot, err := mapClient.VerifySignedMapRoot(setResp.GetMapRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	glog.V(2).Infof("CreateEpoch: SetLeaves:{Revision: %v}", mapRoot.Revision)

	// Write mutations associated with this epoch.
	// TODO(gbelvin): Remove when the monitor reads from the batches table.
	mutations := make([]*ktpb.Entry, 0, len(msgs))
	for _, msg := range msgs {
		mutations = append(mutations, msg.Mutation)
	}
	if err := s.mutations.WriteBatch(ctx, domainID, int64(mapRoot.Revision), mutations); err != nil {
		glog.Errorf("Could not write mutations for revision %v: %v", mapRoot.Revision, err)
		return nil, status.Errorf(codes.Internal, "mutations.WriteBatch(): %v", err)
	}

	mutationCount.Add(float64(len(msgs)), domainID)
	glog.Infof("CreatedEpoch: rev: %v with %v mutations, root: %x", mapRoot.Revision, len(msgs), mapRoot.RootHash)
	return s.PublishBatch(ctx, &spb.PublishBatchRequest{DomainId: domainID})
}

// PublishBatch copies the MapRoots of all known map revisions into the Log of MapRoots.
func (s *Server) PublishBatch(ctx context.Context, in *spb.PublishBatchRequest) (*empty.Empty, error) {
	domain, err := s.ktServer.GetDomain(ctx, &ktpb.GetDomainRequest{DomainId: in.DomainId})
	if err != nil {
		return nil, err
	}

	// Create verifying log and map clients.
	trustedRoot := types.LogRootV1{} // TODO(gbelvin): Store and track trustedRoot.
	logClient, err := tclient.NewFromTree(s.tlog, domain.Log, trustedRoot)
	if err != nil {
		return nil, err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, domain.Map)
	if err != nil {
		return nil, err
	}

	// Get latest log root and map root.
	logRoot, err := logClient.UpdateRoot(ctx)
	if err != nil {
		return nil, err
	}
	rootResp, err := mapClient.Conn.GetSignedMapRoot(ctx, &tpb.GetSignedMapRootRequest{MapId: mapClient.MapID})
	if err != nil {
		return nil, status.Errorf(status.Code(err), "GetSignedMapRoot(%v): %v", mapClient.MapID, err)
	}
	latestMapRoot, err := mapClient.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(%v): %v", mapClient.MapID, err)
	}

	// Add all unpublished map roots to the log.
	for rev := logRoot.TreeSize - 1; rev <= latestMapRoot.Revision; rev++ {
		resp, err := s.tmap.GetSignedMapRootByRevision(ctx, &tpb.GetSignedMapRootByRevisionRequest{
			MapId:    mapClient.MapID,
			Revision: int64(rev),
		})
		if err != nil {
			return nil, status.Errorf(codes.Internal, "GetSignedMapRootByRevision(%v, %v): %v", mapClient.MapID, rev, err)
		}
		rawMapRoot := resp.GetMapRoot()
		mapRoot, err := mapClient.VerifySignedMapRoot(rawMapRoot)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
		}
		if err := logClient.AddSequencedLeaf(ctx, rawMapRoot.GetMapRoot(), int64(mapRoot.Revision)); err != nil {
			glog.Errorf("AddSequencedLeaf(logID: %v, rev: %v): %v", logClient.LogID, mapRoot.Revision, err)
			return nil, err
		}
	}
	// TODO(gbelvin): Remove wait when batching boundaries are deterministic.
	if err := logClient.WaitForInclusion(ctx, rootResp.GetMapRoot().GetMapRoot()); err != nil {
		return nil, status.Errorf(codes.Internal, "WaitForInclusion(): %v", err)
	}
	return &empty.Empty{}, nil
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
