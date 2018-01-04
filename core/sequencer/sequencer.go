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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/internal"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

var (
	mutationsCTR = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kt_signer_mutations",
		Help: "Number of mutations the signer has processed.",
	})
	indexCTR = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "kt_signer_mutations_unique",
		Help: "Number of mutations the signer has processed post per epoch dedupe.",
	})
	mapUpdateHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "kt_signer_map_update_seconds",
		Help:    "Seconds waiting for map update",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, math.Inf(1)},
	})
	createEpochHist = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "kt_signer_create_epoch_seconds",
		Help:    "Seconds spent generating epoch",
		Buckets: []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, math.Inf(1)},
	})
)

// MaxBatchSize limits the number of mutations that will be processed per epoch.
const MaxBatchSize = int32(1000)

func init() {
	prometheus.MustRegister(mutationsCTR)
	prometheus.MustRegister(indexCTR)
	prometheus.MustRegister(mapUpdateHist)
	prometheus.MustRegister(createEpochHist)
}

// Sequencer processes mutations and sends them to the trillian map.
type Sequencer struct {
	domains   domain.Storage
	tmap      trillian.TrillianMapClient
	tlog      trillian.TrillianLogClient
	mutator   mutator.Mutator
	mutations mutator.MutationStorage
	queue     mutator.MutationReciever
	recievers map[string]mutator.Reciever
}

// New creates a new instance of the signer.
func New(domains domain.Storage,
	tmap trillian.TrillianMapClient,
	tlog trillian.TrillianLogClient,
	mutatorF mutator.Mutator,
	mutations mutator.MutationStorage,
	queue mutator.MutationReciever) *Sequencer {
	return &Sequencer{
		domains:   domains,
		tmap:      tmap,
		tlog:      tlog,
		mutator:   mutatorF,
		mutations: mutations,
		recievers: make(map[string]mutator.Reciever),
	}
}

// Close stops all recievers and releases resources.
func (s *Sequencer) Close() {
	for _, r := range s.recievers {
		r.Close()
	}
}

// Initialize inserts the object hash of an empty struct into the log if it is empty.
// This keeps the log leaves in-sync with the map which starts off with an
// empty log root at map revision 0.
func (s *Sequencer) Initialize(ctx context.Context, logID, mapID int64) error {
	logRoot, err := s.tlog.GetLatestSignedLogRoot(ctx, &trillian.GetLatestSignedLogRootRequest{
		LogId: logID,
	})
	if err != nil {
		return fmt.Errorf("GetLatestSignedLogRoot(%v): %v", logID, err)
	}
	mapRoot, err := s.tmap.GetSignedMapRoot(ctx, &trillian.GetSignedMapRootRequest{
		MapId: mapID,
	})
	if err != nil {
		return fmt.Errorf("GetSignedMapRoot(%v): %v", mapID, err)
	}

	// If the tree is empty and the map is empty,
	// add the empty map root to the log.
	if logRoot.GetSignedLogRoot().GetTreeSize() == 0 &&
		mapRoot.GetMapRoot().GetMapRevision() == 0 {
		glog.Infof("Initializing Trillian Log with empty map root")
		if err := queueLogLeaf(ctx, s.tlog, logID, mapRoot.GetMapRoot()); err != nil {
			return err
		}
	}
	return nil
}

// StartSequencingAll starts sequencing processes for all domains.
func (s *Sequencer) StartSequencingAll(ctx context.Context, refresh time.Duration) error {
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
				if _, ok := s.recievers[d.Domain]; !ok {
					glog.Infof("StartSigning domain: %v", d.Domain)
					s.recievers[d.Domain] = s.NewReciever(ctx, d.LogID, d.MapID, d.MinInterval, d.MaxInterval)
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// NewReciever creates a new reciever for mapID.
// New epochs will be created at least once per maxInterval and as often as minInterval.
func (s *Sequencer) NewReciever(ctx context.Context, logID, mapID int64, minInterval, maxInterval time.Duration) mutator.Reciever {
	if err := s.Initialize(ctx, logID, mapID); err != nil {
		glog.Errorf("Initialize() failed: %v", err)
	}
	var rootResp *trillian.GetSignedMapRootResponse
	cctx, cancel := context.WithTimeout(ctx, minInterval)
	rootResp, err := s.tmap.GetSignedMapRoot(cctx, &trillian.GetSignedMapRootRequest{
		MapId: mapID,
	})
	if err != nil {
		glog.Infof("GetSignedMapRoot failed: %v", err)
		// Immediately create new epoch and write new sth:
		if err := s.CreateEpoch(cctx, logID, mapID, nil); err != nil {
			glog.Errorf("CreateEpoch failed: %v", err)
		}
		// Request map head again to get the exact time it was created:
		rootResp, err = s.tmap.GetSignedMapRoot(cctx, &trillian.GetSignedMapRootRequest{
			MapId: mapID,
		})
		if err != nil {
			glog.Errorf("GetSignedMapRoot failed after CreateEpoch: %v", err)
		}
	}
	cancel()
	// Fetch last time from previous map head (as stored in the map server)
	mapRoot := rootResp.GetMapRoot()
	last := time.Unix(0, mapRoot.GetTimestampNanos())
	meta, err := internal.MetadataFromMapRoot(rootResp.GetMapRoot())
	if err != nil {
		glog.Errorf("MeatadataFromMapRoot() failed: %v", err)
	}
	start := meta.GetHighestFullyCompletedSeq()

	return s.queue.NewReciever(ctx, last, mapID, start, func(mutations []*mutator.QueueMessage) error {
		return s.CreateEpoch(ctx, logID, mapID, mutations)
	}, mutator.RecieverOptions{
		MaxBatchSize: 1000,
		Period:       minInterval,
		MaxPeriod:    maxInterval,
	})
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
func (s *Sequencer) applyMutations(mutations []*mutator.QueueMessage, leaves []*trillian.MapLeaf) ([]*trillian.MapLeaf, error) {
	// Put leaves in a map from index to leaf value.
	leafMap := make(map[[32]byte]*trillian.MapLeaf)
	for _, l := range leaves {
		leafMap[toArray(l.Index)] = l
	}

	retMap := make(map[[32]byte]*trillian.MapLeaf)
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

		newValue, err := s.mutator.Mutate(oldValue, m.Mutation)
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

		retMap[toArray(index)] = &trillian.MapLeaf{
			Index:     index,
			LeafValue: leafValue,
			ExtraData: extraData,
		}
	}
	// Convert return map back into a list.
	ret := make([]*trillian.MapLeaf, 0, len(retMap))
	for _, v := range retMap {
		ret = append(ret, v)
	}
	return ret, nil
}

// CreateEpoch signs the current map head.
func (s *Sequencer) CreateEpoch(ctx context.Context, logID, mapID int64, mutations []*mutator.QueueMessage) error {
	glog.V(2).Infof("CreateEpoch: starting sequencing run")
	start := time.Now()
	// Get the current root.
	rootResp, err := s.tmap.GetSignedMapRoot(ctx, &trillian.GetSignedMapRootRequest{
		MapId: mapID,
	})
	if err != nil {
		return fmt.Errorf("GetSignedMapRoot(%v): %v", mapID, err)
	}
	meta, err := internal.MetadataFromMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return err
	}
	if meta.GetHighestFullyCompletedSeq() == 0 {
		glog.Infof("Sequencer.CreateEpoch: Map Root probably has no metadata yet")
	}
	startSeq := meta.GetHighestFullyCompletedSeq()
	revision := rootResp.GetMapRoot().GetMapRevision()
	glog.V(3).Infof("CreateEpoch: Previous SignedMapRoot: {Revision: %v, HighestFullyCompletedSeq: %v}", revision, startSeq)

	// Get current leaf values.
	indexes := make([][]byte, 0, len(mutations))
	for _, m := range mutations {
		indexes = append(indexes, m.Mutation.Index)
	}
	glog.V(2).Infof("CreateEpoch: len(mutations): %v, len(indexes): %v",
		len(mutations), len(indexes))
	getResp, err := s.tmap.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
		MapId: mapID,
		Index: indexes,
	})
	if err != nil {
		return err
	}
	glog.V(3).Infof("CreateEpoch: len(GetLeaves.MapLeafInclusions): %v",
		len(getResp.MapLeafInclusion))

	// Trust the leaf values provided by the map server.
	// If the map server is run by an untrusted entity, perform inclusion
	// and signature verification here.
	leaves := make([]*trillian.MapLeaf, 0, len(getResp.MapLeafInclusion))
	for _, m := range getResp.MapLeafInclusion {
		leaves = append(leaves, m.Leaf)
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(mutations, leaves)
	if err != nil {
		return err
	}
	glog.V(2).Infof("CreateEpoch: applied %v mutations to %v leaves",
		len(mutations), len(leaves))

	var max int64
	for _, m := range mutations {
		if m.ID > max {
			max = m.ID
		}
	}

	metaAny, err := internal.MetadataAsAny(&pb.MapperMetadata{
		HighestFullyCompletedSeq: max,
	})
	if err != nil {
		return err
	}

	// Set new leaf values.
	mapSetStart := time.Now()
	setResp, err := s.tmap.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
		MapId:    mapID,
		Leaves:   newLeaves,
		Metadata: metaAny,
	})
	mapSetEnd := time.Now()
	if err != nil {
		return err
	}
	revision = setResp.GetMapRoot().GetMapRevision()
	glog.V(2).Infof("CreateEpoch: SetLeaves:{Revision: %v, HighestFullyCompletedSeq: %v}", revision, max)

	// Put SignedMapHead in an append only log.
	if err := queueLogLeaf(ctx, s.tlog, logID, setResp.GetMapRoot()); err != nil {
		// TODO(gdbelvin): If the log doesn't do this, we need to generate an emergency alert.
		return err
	}

	mutationsCTR.Add(float64(len(mutations)))
	indexCTR.Add(float64(len(indexes)))
	mapUpdateHist.Observe(mapSetEnd.Sub(mapSetStart).Seconds())
	createEpochHist.Observe(time.Since(start).Seconds())
	glog.Infof("CreatedEpoch: rev: %v, root: %x", revision, setResp.GetMapRoot().GetRootHash())
	return nil
}

// TODO(gdbelvin): Add leaf at a specific index. trillian#423
func queueLogLeaf(ctx context.Context, tlog trillian.TrillianLogClient, logID int64, smr *trillian.SignedMapRoot) error {
	smrJSON, err := json.Marshal(smr)
	if err != nil {
		return err
	}
	idHash := sha256.Sum256(smrJSON)

	if _, err := tlog.QueueLeaf(ctx, &trillian.QueueLeafRequest{
		LogId: logID,
		Leaf: &trillian.LogLeaf{
			LeafValue:        smrJSON,
			LeafIdentityHash: idHash[:],
		},
	}); err != nil {
		return fmt.Errorf("trillianLog.QueueLeaf(logID: %v, leaf: %v): %v",
			logID, smrJSON, err)
	}
	return nil
}
