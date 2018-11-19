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
	"bytes"
	"context"

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/mutator/entry"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

func (s *Server) createRevisionWithBeam(ctx context.Context, in *spb.CreateRevisionRequest,
	metaProto *spb.MapMetadata) error {
	readBatchSize := int32(1000) // TODO(gbelvin): Make configurable.

	p := beam.NewPipeline()
	scope := p.Root()

	req := beam.Create(scope, in)
	meta := beam.Create(scope, metaProto)
	// Read each logID in parallel.
	sourceSlices := beam.ParDo(scope, splitMeta, meta) // KV<logID, source>
	logItems := beam.ParDo(scope, s.readOneLog, sourceSlices,
		beam.SideInput{Input: beam.Create(scope, in.DirectoryId)},
		beam.SideInput{Input: beam.Create(scope, readBatchSize)}) // *ktpb.EntryUpdate

	keyedMutations := beam.ParDo(scope, mapLogItem, logItems) // KV<index, *ktpb.EntryUpdate>

	// Read the map
	indexes := beam.Combine(scope, &mergeIndexFn{}, beam.DropValue(scope, keyedMutations)) // []index
	mapLeaves := beam.ParDo(scope, s.readMap, indexes, beam.SideInput{Input: req})         // KV<index, *tpb.MapLeaf>

	// Align MapLeaves with their mutations and apply mutations.
	joined := beam.CoGroupByKey(scope, mapLeaves, keyedMutations) // []*tpb.MapLeaf, []*ktpb.EntryUpdate
	newMapLeaves := beam.ParDo(scope, applyMutation, joined)      // *tpb.MapLeaf

	// Collect all new map leaves.
	allMapLeaves := beam.Combine(scope, &mergeMapLeavesFn{}, newMapLeaves) // []*tpb.MapLeaf

	// Write to map.
	beam.ParDo0(scope, s.writeMap, allMapLeaves,
		beam.SideInput{Input: meta},
		beam.SideInput{Input: req})

	return beamx.Run(ctx, p)
}

// splitMeta emits one KV<logID, source> for each source in the directoryID/Revision batch.
func splitMeta(meta *spb.MapMetadata, emit func(logID int64, source *spb.MapMetadata_SourceSlice)) {
	for logID, source := range meta.Sources {
		glog.Infof("emit(logID %v, source %v)", logID, source)
		emit(logID, source)
	}
}

// readOneLog reads from source.LowestWatermark to source.HighestWatermark in
// increments of batchSize, emitting *ktpb.EntryUpdates as it goes.
func (s *Server) readOneLog(ctx context.Context, logID int64, source *spb.MapMetadata_SourceSlice,
	directoryID string, batchSize int32, emit func(*ktpb.EntryUpdate)) error {
	low := source.GetLowestWatermark()
	high := source.GetHighestWatermark()
	// Loop until less than batchSize items are returned.
	for count := batchSize; count == batchSize; {
		batch, err := s.logs.ReadLog(ctx, directoryID, logID, low, high, batchSize)
		if err != nil {
			return status.Errorf(codes.Internal, "ReadLog(): %v", err)
		}
		for _, m := range batch {
			glog.Infof("emit(logID: %v, %v : EntryUpdate)", logID, m.ID)
			emit(&ktpb.EntryUpdate{
				Mutation:  m.Mutation,
				Committed: m.ExtraData,
			})
			if m.ID > low {
				low = m.ID
			}
		}
		count = int32(len(batch))
		glog.Infof("ReadLog(%v, (%v, %v], %v) count: %v", logID, low, high, batchSize, count)
	}
	return nil
}

// mapLogItem takes an individual entry and emits KV<index, mutation>
func mapLogItem(e *ktpb.EntryUpdate, emit func(index []byte, update *ktpb.EntryUpdate)) error {
	var entry ktpb.Entry
	if err := proto.Unmarshal(e.GetMutation().GetEntry(), &entry); err != nil {
		return err
	}
	emit(entry.Index, e)
	return nil
}

type mergeIndexFn struct{}

func (*mergeIndexFn) CreateAccumulator() [][]byte                 { return [][]byte{} }
func (*mergeIndexFn) AddInput(list [][]byte, val []byte) [][]byte { return append(list, val) }
func (*mergeIndexFn) ExtractOutput(list [][]byte) [][]byte        { return list }
func (*mergeIndexFn) MergeAccumulators(list [][][]byte) [][]byte {
	ret := [][]byte{}
	for _, l := range list {
		for _, i := range l {
			ret = append(ret, i)
		}
	}
	return ret
}

// readMap queries the Trillian map for a list of leaves and emits KV<index, MapLeaf>
func (s *Server) readMap(ctx context.Context, indexes [][]byte, in *spb.CreateRevisionRequest,
	emit func(index []byte, leaf *tpb.MapLeaf)) error {
	// Fetch verification objects for directoryID.
	config, err := s.ktServer.GetDirectory(ctx, &ktpb.GetDirectoryRequest{DirectoryId: in.DirectoryId})
	if err != nil {
		return err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, config.Map)
	if err != nil {
		return err
	}
	// TODO(gbelvin): Fetch map leaves at a specific revision.
	leaves, err := mapClient.GetAndVerifyMapLeaves(ctx, indexes)
	if err != nil {
		return err
	}
	for _, l := range leaves {
		emit(l.Index, l)
	}
	return nil
}

// applyMutation processes all the mutations for a given index and emits the new map leaf.
func applyMutation(index []byte, getMapLeaf func(**tpb.MapLeaf) bool, getMessage func(**ktpb.EntryUpdate) bool,
	emit func(*tpb.MapLeaf)) error {
	var oldMapLeaf *tpb.MapLeaf
	if !getMapLeaf(&oldMapLeaf) {
		return status.Errorf(codes.NotFound, "no map leaf found for index %x", index)
	}
	oldValue, err := entry.FromLeafValue(oldMapLeaf.LeafValue)
	if err != nil {
		glog.Warningf("entry.FromLeafValue(%v): %v", oldMapLeaf.LeafValue, err)
		return err
	}

	var newEntry *ktpb.SignedEntry
	var committed *ktpb.Committed
	var msg *ktpb.EntryUpdate
	for getMessage(&msg) {
		newValue, err := entry.New().Mutate(oldValue, msg.Mutation)
		if err != nil {
			glog.Warningf("Mutate(): %v", err)
			continue // Filter for valid mutations.
		}
		// The order of mutations needs to be associative we need to break ties without regard to the order of messages.
		if bytes.Compare(newValue.Entry, newEntry.GetEntry()) > 0 {
			newEntry = newValue
			committed = msg.Committed
		}
	}
	if newEntry == nil {
		glog.Warningf("no valid mutations found for index %x", index)
		return nil
	}

	leafValue, err := entry.ToLeafValue(newEntry)
	if err != nil {
		glog.Warningf("ToLeafValue(): %v", err)
		return err
	}
	extraData, err := proto.Marshal(committed)
	if err != nil {
		glog.Warningf("proto.Marshal(): %v", err)
		return err
	}
	emit(&tpb.MapLeaf{
		Index:     index,
		LeafValue: leafValue,
		ExtraData: extraData,
	})
	return nil
}

type mergeMapLeavesFn struct{}

func (*mergeMapLeavesFn) CreateAccumulator() []*tpb.MapLeaf { return []*tpb.MapLeaf{} }
func (*mergeMapLeavesFn) AddInput(list []*tpb.MapLeaf, val *tpb.MapLeaf) []*tpb.MapLeaf {
	return append(list, val)
}
func (*mergeMapLeavesFn) ExtractOutput(list []*tpb.MapLeaf) []*tpb.MapLeaf { return list }
func (*mergeMapLeavesFn) MergeAccumulators(list [][]*tpb.MapLeaf) []*tpb.MapLeaf {
	ret := []*tpb.MapLeaf{}
	for _, l := range list {
		for _, i := range l {
			ret = append(ret, i)
		}
	}
	return ret
}

// writeMap takes a list of map leaves and writes them to the Trillian Map.
func (s *Server) writeMap(ctx context.Context, leaves []*tpb.MapLeaf, meta *spb.MapMetadata, in *spb.CreateRevisionRequest) error {
	glog.Infof("writeMap: for %v with %d leaves", in.DirectoryId, len(leaves))
	config, err := s.ktServer.GetDirectory(ctx, &ktpb.GetDirectoryRequest{DirectoryId: in.DirectoryId})
	if err != nil {
		return err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, config.Map)
	if err != nil {
		return err
	}

	// Serialize metadata
	metadata, err := proto.Marshal(meta)
	if err != nil {
		return err
	}

	// Set new leaf values.
	setResp, err := s.tmap.SetLeaves(ctx, &tpb.SetMapLeavesRequest{
		MapId:    config.Map.TreeId,
		Leaves:   leaves,
		Metadata: metadata,
	})
	if err != nil {
		return status.Errorf(codes.Internal, "tmap.SetLeaves(): %v", err)
	}
	mapRoot, err := mapClient.VerifySignedMapRoot(setResp.GetMapRoot())
	if err != nil {
		return status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	glog.V(2).Infof("CreateRevision: SetLeaves:{Revision: %v}", mapRoot.Revision)
	return nil
}
