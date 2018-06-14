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

// Package sequencer reads mutations and applies them to the Trillian Map.
package sequencer

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/monitoring"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

const (
	// MaxBatchSize limits the number of mutations that will be processed per epoch.
	MaxBatchSize  = int32(1000)
	domainIDLabel = "domainid"
)

var (
	once               sync.Once
	knownDomains       monitoring.Gauge
	mutationsCTR       monitoring.Counter
	sequencingRuns     monitoring.Counter
	sequencingFailures monitoring.Counter
	sequencingLatency  monitoring.Histogram
)

func createMetrics(mf monitoring.MetricFactory) {
	knownDomains = mf.NewGauge(
		"known_domains",
		"Set to 1 for known domains (whether this instance is master or not)",
		domainIDLabel)
	mutationsCTR = mf.NewCounter(
		"mutations",
		"Number of mutations the signer has processed",
		domainIDLabel)
	sequencingRuns = mf.NewCounter(
		"sequencing_runs",
		"Number of times a sequencing run has been attempted",
		domainIDLabel)
	sequencingFailures = mf.NewCounter(
		"sequencing_errors",
		"Number of times a sequencing run has failed",
		domainIDLabel)
	sequencingLatency = mf.NewHistogram(
		"sequencing_latency",
		"Time taken to complete a sequencing run",
		domainIDLabel)
}

// Sequencer processes mutations and sends them to the trillian map.
type Sequencer struct {
	domains     domain.Storage
	logAdmin    tpb.TrillianAdminClient
	tlog        tpb.TrillianLogClient
	mapAdmin    tpb.TrillianAdminClient
	tmap        tpb.TrillianMapClient
	mutatorFunc mutator.Func
	mutations   mutator.MutationStorage
	queue       mutator.MutationQueue
	receivers   map[string]mutator.Receiver
}

// New creates a new instance of the signer.
func New(tlog tpb.TrillianLogClient,
	logAdmin tpb.TrillianAdminClient,
	tmap tpb.TrillianMapClient,
	mapAdmin tpb.TrillianAdminClient,
	mutatorFunc mutator.Func,
	domains domain.Storage,
	mutations mutator.MutationStorage,
	queue mutator.MutationQueue,
	metricsFactory monitoring.MetricFactory) *Sequencer {
	once.Do(func() { createMetrics(metricsFactory) })

	return &Sequencer{
		domains:     domains,
		tlog:        tlog,
		logAdmin:    logAdmin,
		tmap:        tmap,
		mapAdmin:    mapAdmin,
		mutatorFunc: mutatorFunc,
		mutations:   mutations,
		queue:       queue,
		receivers:   make(map[string]mutator.Receiver),
	}
}

// Close stops all receivers and releases resources.
func (s *Sequencer) Close() {
	for _, r := range s.receivers {
		r.Close()
	}
}

// ListenForNewDomains starts receivers for all domains and periodically checks for new domains.
func (s *Sequencer) ListenForNewDomains(ctx context.Context, refresh time.Duration) error {
	ticker := time.NewTicker(refresh)
	defer func() { ticker.Stop() }()

	for {
		select {
		case <-ticker.C:
			domains, err := s.domains.List(ctx, false)
			if err != nil {
				return fmt.Errorf("admin.List(): %v", err)
			}
			for _, d := range domains {
				knownDomains.Set(1.0, d.DomainID)
				if _, ok := s.receivers[d.DomainID]; !ok {
					glog.Infof("StartSigning domain: %v", d.DomainID)
					r, err := s.NewReceiver(ctx, d)
					if err != nil {
						return err
					}
					s.receivers[d.DomainID] = r
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// NewReceiver creates a new receiver for a domain.
// New epochs will be created at least once per maxInterval and as often as minInterval.
func (s *Sequencer) NewReceiver(ctx context.Context, d *domain.Domain) (mutator.Receiver, error) {
	cctx, cancel := context.WithTimeout(ctx, d.MinInterval)
	defer cancel()
	mapTree, err := s.mapAdmin.GetTree(cctx, &tpb.GetTreeRequest{TreeId: d.MapID})
	if err != nil {
		return nil, err
	}
	mapVerifier, err := tclient.NewMapVerifierFromTree(mapTree)
	if err != nil {
		return nil, err
	}

	rootResp, err := s.tmap.GetSignedMapRoot(cctx, &tpb.GetSignedMapRootRequest{MapId: d.MapID})
	if err != nil {
		return nil, err
	}
	cancel()
	// Fetch last time from previous map head (as stored in the map server)
	mapRoot, err := mapVerifier.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return nil, err
	}
	last := time.Unix(0, int64(mapRoot.TimestampNanos))

	logTree, err := s.logAdmin.GetTree(ctx, &tpb.GetTreeRequest{TreeId: d.LogID})
	if err != nil {
		return nil, err
	}
	logClient, err := tclient.NewFromTree(s.tlog, logTree)
	if err != nil {
		return nil, err
	}

	return s.queue.NewReceiver(ctx, last, d.DomainID, func(mutations []*mutator.QueueMessage) error {
		return s.createEpoch(ctx, d, logClient, mapVerifier, mutations)
	}, mutator.ReceiverOptions{
		MaxBatchSize: MaxBatchSize,
		Period:       d.MinInterval,
		MaxPeriod:    d.MaxInterval,
	}), nil
}

// toArray returns the first 32 bytes from b.
// If b is less than 32 bytes long, the output is zero padded.
func toArray(b []byte) [32]byte {
	var i [32]byte
	copy(i[:], b)
	return i
}

// applyMutations takes the set of mutations and applies them to given leafs.
// Multiple mutations for the same leaf will be applied to provided leaf.
// The last valid mutation for each leaf is included in the output.
// Returns a list of map leaves that should be updated.
func (s *Sequencer) applyMutations(mutations []*mutator.QueueMessage, leaves []*tpb.MapLeaf) ([]*tpb.MapLeaf, error) {
	// Put leaves in a map from index to leaf value.
	leafMap := make(map[[32]byte]*tpb.MapLeaf)
	for _, l := range leaves {
		leafMap[toArray(l.Index)] = l
	}

	retMap := make(map[[32]byte]*tpb.MapLeaf)
	for _, m := range mutations {
		index := m.Mutation.GetIndex()
		var oldValue *pb.Entry // If no map leaf was found, oldValue will be nil.
		if leaf, ok := leafMap[toArray(index)]; ok {
			var err error
			oldValue, err = entry.FromLeafValue(leaf.GetLeafValue())
			if err != nil {
				glog.Warningf("entry.FromLeafValue(%v): %v", leaf.GetLeafValue(), err)
				continue
			}
		}

		newValue, err := s.mutatorFunc.Mutate(oldValue, m.Mutation)
		if err != nil {
			glog.Warningf("Mutate(): %v", err)
			continue // A bad mutation should not make the whole batch fail.
		}
		leafValue, err := entry.ToLeafValue(newValue)
		if err != nil {
			glog.Warningf("ToLeafValue(): %v", err)
			continue
		}

		// Serialize commitment.
		extraData, err := proto.Marshal(m.ExtraData)
		if err != nil {
			glog.Warningf("Marshal(committed proto): %v", err)
			continue
		}

		retMap[toArray(index)] = &tpb.MapLeaf{
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
	return ret, nil
}

// createEpoch signs the current map head.
func (s *Sequencer) createEpoch(ctx context.Context, d *domain.Domain, logClient *tclient.LogClient, mapVerifier *tclient.MapVerifier, msgs []*mutator.QueueMessage) error {
	glog.Infof("CreateEpoch: starting sequencing run with %d mutations", len(msgs))
	start := time.Now()
	sequencingRuns.Inc(d.DomainID)
	// Get the current root.
	rootResp, err := s.tmap.GetSignedMapRoot(ctx, &tpb.GetSignedMapRootRequest{MapId: d.MapID})
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return fmt.Errorf("GetSignedMapRoot(%v): %v", d.MapID, err)
	}
	mapRoot, err := mapVerifier.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return err
	}
	glog.V(3).Infof("CreateEpoch: Previous SignedMapRoot: {Revision: %v}", mapRoot.Revision)

	// Get current leaf values.
	indexes := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		indexes = append(indexes, m.Mutation.Index)
	}
	glog.V(2).Infof("CreateEpoch: len(mutations): %v, len(indexes): %v", len(msgs), len(indexes))
	getResp, err := s.tmap.GetLeaves(ctx, &tpb.GetMapLeavesRequest{
		MapId: d.MapID,
		Index: indexes,
	})
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return err
	}
	glog.V(3).Infof("CreateEpoch: len(GetLeaves.MapLeafInclusions): %v",
		len(getResp.MapLeafInclusion))

	// Trust the leaf values provided by the map server.
	// If the map server is run by an untrusted entity, perform inclusion
	// and signature verification here.
	leaves := make([]*tpb.MapLeaf, 0, len(getResp.MapLeafInclusion))
	for _, m := range getResp.MapLeafInclusion {
		leaves = append(leaves, m.Leaf)
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(msgs, leaves)
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return err
	}
	glog.V(2).Infof("CreateEpoch: applied %v mutations to %v leaves", len(msgs), len(leaves))

	// Set new leaf values.
	setResp, err := s.tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		MapId:  d.MapID,
		Leaves: newLeaves,
	})
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return err
	}
	mapRoot, err = mapVerifier.VerifySignedMapRoot(setResp.GetMapRoot())
	if err != nil {
		sequencingFailures.Inc(d.DomainID)
		return err
	}
	glog.V(2).Infof("CreateEpoch: SetLeaves:{Revision: %v}", mapRoot.Revision)

	// Write mutations associated with this epoch.
	mutations := make([]*pb.Entry, 0, len(msgs))
	for _, msg := range msgs {
		mutations = append(mutations, msg.Mutation)
	}
	if err := s.mutations.WriteBatch(ctx, d.DomainID, int64(mapRoot.Revision), mutations); err != nil {
		glog.Fatalf("Could not write mutations for revision %v: %v", mapRoot.Revision, err)
		sequencingFailures.Inc(d.DomainID)
		return err
	}

	// Put SignedMapHead in an append only log.
	if err := logClient.AddSequencedLeafAndWait(ctx, setResp.GetMapRoot().GetMapRoot(), int64(mapRoot.Revision)); err != nil {
		sequencingFailures.Inc(d.DomainID)
		glog.Fatalf("AddSequencedLeaf(logID: %v, rev: %v): %v", d.LogID, mapRoot.Revision, err)
		// TODO(gdbelvin): If the log doesn't do this, we need to generate an emergency alert.
		return err
	}

	mutationsCTR.Add(float64(len(msgs)), d.DomainID)
	sequencingLatency.Observe(time.Since(start).Seconds(), d.DomainID)
	glog.Infof("CreatedEpoch: rev: %v with %v mutations, root: %x", mapRoot.Revision, len(msgs), mapRoot.RootHash)
	return nil
}
