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

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/types"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

const (
	directoryIDLabel = "directoryid"
	reasonLabel      = "reason"
)

var (
	once             sync.Once
	knownDirectories monitoring.Gauge
	batchSize        monitoring.Gauge
	mutationCount    monitoring.Counter
	mutationFailures monitoring.Counter
)

func createMetrics(mf monitoring.MetricFactory) {
	knownDirectories = mf.NewGauge(
		"known_directories",
		"Set to 1 for known directories (whether this instance is master or not)",
		directoryIDLabel)
	mutationCount = mf.NewCounter(
		"mutation_count",
		"Number of mutations the signer has processed for directoryid since process start",
		directoryIDLabel)
	mutationFailures = mf.NewCounter(
		"mutation_failures",
		"Number of invalid mutations the signer has processed for directoryid since process start",
		directoryIDLabel, reasonLabel)
	batchSize = mf.NewGauge(
		"batch_size",
		"Number of mutations the signer is attempting to process for directoryid",
		directoryIDLabel)
}

// SourcesEntry is a map of SourceSlices by logID.
type SourcesEntry map[int64]*spb.MapMetadata_SourceSlice

// Watermarks is a map of watermarks by logID.
type Watermarks map[int64]int64

// LogsReader reads messages in multiple logs.
type LogsReader interface {
	// HighWatermark returns the number of items and the highest primary
	// key up to batchSize items after start (exclusive).
	HighWatermark(ctx context.Context, directoryID string, logID, start int64,
		batchSize int32) (count int32, watermark int64, err error)

	// ListLogs returns the logIDs associated with directoryID that have their write bits set,
	// or all logIDs associated with directoryID if writable is false.
	ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error)

	// ReadLog returns the lowest messages in the (low, high] range stored in the
	// specified log, up to batchSize.  Paginate by setting low to the
	// highest LogMessage returned in the previous page.
	ReadLog(ctx context.Context, directoryID string, logID, low, high int64,
		batchSize int32) ([]*mutator.LogMessage, error)
}

// Batcher writes batch definitions to storage.
type Batcher interface {
	// WriteBatchSources saves the (low, high] boundaries used for each log in making this revision.
	WriteBatchSources(ctx context.Context, dirID string, rev int64, meta *spb.MapMetadata) error
	// ReadBatch returns the batch definitions for a given revision.
	ReadBatch(ctx context.Context, directoryID string, rev int64) (*spb.MapMetadata, error)
}

// Server implements KeyTransparencySequencerServer.
type Server struct {
	ktServer *keyserver.Server
	batcher  Batcher
	tmap     tpb.TrillianMapClient
	tlog     tpb.TrillianLogClient
	logs     LogsReader
}

// NewServer creates a new KeyTransparencySequencerServer.
func NewServer(
	directories directory.Storage,
	logAdmin tpb.TrillianAdminClient,
	mapAdmin tpb.TrillianAdminClient,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	batcher Batcher,
	logs LogsReader,
	metricsFactory monitoring.MetricFactory,
) *Server {
	once.Do(func() { createMetrics(metricsFactory) })
	return &Server{
		ktServer: keyserver.New(nil, nil, logAdmin, mapAdmin, nil, directories, nil, nil),
		tlog:     tlog,
		tmap:     tmap,
		batcher:  batcher,
		logs:     logs,
	}
}

// RunBatch runs the full sequence of steps (for one directory) nessesary to get a
// mutation from the log integrated into the map. This consists of a series of
// idempotent steps:
// a) assign a batch of mutations from the logs to a map revision
// b) apply the batch to the map
// c) publish existing map roots to a log of SignedMapRoots.
func (s *Server) RunBatch(ctx context.Context, in *spb.RunBatchRequest) (*empty.Empty, error) {
	// Get the previous and current high water marks.
	directory, err := s.ktServer.GetDirectory(ctx, &ktpb.GetDirectoryRequest{DirectoryId: in.DirectoryId})
	if err != nil {
		return nil, err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, directory.Map)
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

	startWatermarks := make(Watermarks)
	for logID, source := range lastMeta.Sources {
		startWatermarks[logID] = source.HighestWatermark
	}
	count, highs, err := s.HighWatermarks(ctx, in.DirectoryId, startWatermarks, in.MaxBatch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "HighWatermarks(): %v", err)
	}
	meta := &spb.MapMetadata{Sources: make(SourcesEntry)}
	for logID, high := range highs {
		meta.Sources[logID] = &spb.MapMetadata_SourceSlice{
			LowestWatermark:  startWatermarks[logID],
			HighestWatermark: high,
		}
	}

	//
	// Rate limit the creation of new batches.
	//

	// TODO(#1057): If time since last map revision > max timeout, define batch.
	// TODO(#1047): If time since oldest queue item > max latency has elapsed, define batch.
	// If count items >= min_batch, define batch.
	if count >= in.MinBatch {
		nextRev := int64(latestMapRoot.Revision) + 1
		if err := s.batcher.WriteBatchSources(ctx, in.DirectoryId, nextRev, meta); err != nil {
			return nil, status.Errorf(codes.AlreadyExists, "%v rev %v already exists: %v",
				in.DirectoryId, nextRev, err)
		}

		return s.CreateRevision(ctx, &spb.CreateRevisionRequest{
			DirectoryId: in.DirectoryId,
			Revision:    nextRev,
		})
	}

	// TODO(#1056): If count items == max_batch, should we define the next batch immediately?
	return &empty.Empty{}, nil
}

// CreateRevision applies the supplied mutations to the current map revision and creates a new revision.
func (s *Server) CreateRevision(ctx context.Context, in *spb.CreateRevisionRequest) (*empty.Empty, error) {
	readBatchSize := int32(1000) // TODO(gbelvin): Make configurable.

	p := beam.NewPipeline()
	scope := p.Root()

	req := beam.Create(scope, in)
	// Read each logID in parallel.
	logItems := beam.ParDo(scope, s.readOneLog,
		beam.ParDo(scope, s.readBatch, req), // KV<logID, source>
		beam.SideInput{Input: beam.Create(scope, in.DirectoryId)},
		beam.SideInput{Input: beam.Create(scope, readBatchSize)}) // *ktpb.EntryUpdate

	// Globally combine the KV<logID, source> slices into a single *spb.MapMetadata.
	// Under the covers this gives all elements the same key, then groups by key.
	metaSlices := beam.ParDo(scope, mapMeta, sourcesSlices) // *spb.MapMetadata
	meta := beam.Combine(scope, mergeMeta, metaSlices)      // *spb.MapMetadata

	// Globally combine all the *ktpb.EntryUpdates into a single []*ktpb.EntryUpdate
	// TODO(gbelvin): Further split ApplyBatch into parallel steps, so we don't need to do this.
	groupedLogItems := beam.ParDo(scope, mapLogItem, logItems)              // []*ktpb.EntryUpdate
	combinedLogItems := beam.Combine(scope, mergeLogItems, groupedLogItems) // []*ktpb.EntryUpdate

	//
	beam.ParDo0(scope, s.ApplyBatch, combinedLogItems, // []*ktpb.EntryUpdate
		beam.SideInput{Input: meta},
		beam.SideInput{Input: req})

	// TODO(gbelvin): Further split ApplyBatch
	// 1. Map *ktpb.EntryUpdate to KV<index, EntryUpdate>
	// 2. DropValue and Combine all indexes
	// 3. GetMapLeavesAtRevsion(all indexes), emit KV<index, MapLeaf>
	// 4. CoGroupByKey
	// 5. ParDo ApplyMutation(key, []EntryUpdate, MapLeaf) emit MapLeaf
	// 6. Collect []MapLeaf
	// 7. ParDo WriteMapLeaves

	if err := beamx.Run(ctx, p); err != nil {
		return nil, err
	}

	return s.PublishBatch(ctx, &spb.PublishBatchRequest{DirectoryId: in.DirectoryId})
}

// readBatch emits one KV<logID, source> for each source in the directoryID/Revision batch.
func (s *Server) readBatch(ctx context.Context, in *spb.CreateRevisionRequest, emit func(logID int64, source *spb.MapMetadata_SourceSlice)) error {
	glog.Infof("ReadBach for rev %v", in.Revision)
	meta, err := s.batcher.ReadBatch(ctx, in.DirectoryId, in.Revision)
	if err != nil {
		return status.Errorf(codes.Internal, "ReadBatch(%v, %v): %v", in.DirectoryId, in.Revision, err)
	}
	for logID, source := range meta.Sources {
		glog.Infof("emit(logID %v, source %v)", logID, source)
		emit(logID, source)
	}
	return nil
}

// readOneLog reads from source.LowestWatermark to source.HighestWatermark in increments of batchSize, emitting *ktpb.EntryUpdates as it goes.
func (s *Server) readOneLog(ctx context.Context, logID int64, source *spb.MapMetadata_SourceSlice, directoryID string, batchSize int32,
	emit func(*ktpb.EntryUpdate)) error {
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

// mapLogItem takes an individual entry and emits a list of entries.
// This allows EntryUpdates to be aggregated.
func mapLogItem(a *ktpb.EntryUpdate) []*ktpb.EntryUpdate {
	return []*ktpb.EntryUpdate{a}
}

// mergeLogItems takes two lists of items and produces a unified list.
func mergeLogItems(a, b []*ktpb.EntryUpdate) []*ktpb.EntryUpdate {
	for _, m := range b {
		a = append(a, m)
	}
	glog.Infof("mergeLogItems: %v", a)
	return a
}

func mapMeta(logID int64, source *spb.MapMetadata_SourceSlice) *spb.MapMetadata {
	return &spb.MapMetadata{
		Sources: map[int64]*spb.MapMetadata_SourceSlice{logID: source},
	}
}

func mergeMeta(a, b *spb.MapMetadata) *spb.MapMetadata {
	for k, v := range b.Sources {
		a.Sources[k] = v
	}
	glog.Infof("mergeMeta: %v", a)
	return a
}

// ApplyBatch takes a set of inputs and applies them to a specifc map revision.
func (s *Server) ApplyBatch(ctx context.Context, msgs []*ktpb.EntryUpdate, meta *spb.MapMetadata, in *spb.CreateRevisionRequest) error {
	glog.Infof("ApplyBatch: for %v with %d messages", in.DirectoryId, len(msgs))
	// Fetch verification objects for directoryID.
	config, err := s.ktServer.GetDirectory(ctx, &ktpb.GetDirectoryRequest{DirectoryId: in.DirectoryId})
	if err != nil {
		return err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, config.Map)
	if err != nil {
		return err
	}

	// Parse mutations using the mutator for this directory.
	batchSize.Set(float64(len(msgs)), config.DirectoryId)
	indexes := make([][]byte, 0, len(msgs))
	for _, m := range msgs {
		var entry ktpb.Entry
		if err := proto.Unmarshal(m.Mutation.Entry, &entry); err != nil {
			return err
		}
		indexes = append(indexes, entry.Index)
	}
	glog.V(2).Infof("CreateRevision: %v mutations, %v indexes", len(msgs), len(indexes))

	// TODO(gbelvin): Fetch map leaves at a specific revision.
	leaves, err := mapClient.GetAndVerifyMapLeaves(ctx, indexes)
	if err != nil {
		return err
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(in.DirectoryId, entry.New(), msgs, leaves)
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
		Leaves:   newLeaves,
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

	mutationCount.Add(float64(len(msgs)), in.DirectoryId)
	glog.Infof("CreatedRevision: rev: %v with %v mutations, root: %x", mapRoot.Revision, len(msgs), mapRoot.RootHash)
	return nil
}

// PublishBatch copies the MapRoots of all known map revisions into the Log of MapRoots.
func (s *Server) PublishBatch(ctx context.Context, in *spb.PublishBatchRequest) (*empty.Empty, error) {
	directory, err := s.ktServer.GetDirectory(ctx, &ktpb.GetDirectoryRequest{DirectoryId: in.DirectoryId})
	if err != nil {
		return nil, err
	}

	// Create verifying log and map clients.
	trustedRoot := types.LogRootV1{} // TODO(gbelvin): Store and track trustedRoot.
	logClient, err := tclient.NewFromTree(s.tlog, directory.Log, trustedRoot)
	if err != nil {
		return nil, err
	}
	mapClient, err := tclient.NewMapClientFromTree(s.tmap, directory.Map)
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
			return nil, status.Errorf(codes.Internal,
				"GetSignedMapRootByRevision(%v, %v): %v",
				mapClient.MapID, rev, err)
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
func (s *Server) applyMutations(directoryID string, mutatorFunc mutator.Func,
	msgs []*ktpb.EntryUpdate, leaves []*tpb.MapLeaf) ([]*tpb.MapLeaf, error) {
	// Put leaves in a map from index to leaf value.
	leafMap := make(map[string]*tpb.MapLeaf)
	for _, l := range leaves {
		leafMap[string(l.Index)] = l
	}

	retMap := make(map[string]*tpb.MapLeaf)
	for _, msg := range msgs {
		var e ktpb.Entry
		if err := proto.Unmarshal(msg.Mutation.Entry, &e); err != nil {
			return nil, err
		}
		var oldValue *ktpb.SignedEntry // If no map leaf was found, oldValue will be nil.
		if leaf, ok := leafMap[string(e.Index)]; ok {
			var err error
			oldValue, err = entry.FromLeafValue(leaf.GetLeafValue())
			if err != nil {
				glog.Warningf("entry.FromLeafValue(%v): %v", leaf.GetLeafValue(), err)
				mutationFailures.Inc(directoryID, "Unmarshal")
				continue
			}
		}

		newValue, err := mutatorFunc.Mutate(oldValue, msg.Mutation)
		if err != nil {
			glog.Warningf("Mutate(): %v", err)
			mutationFailures.Inc(directoryID, "Mutate")
			continue // A bad mutation should not make the whole batch fail.
		}
		leafValue, err := entry.ToLeafValue(newValue)
		if err != nil {
			glog.Warningf("ToLeafValue(): %v", err)
			mutationFailures.Inc(directoryID, "Marshal")
			continue
		}
		extraData, err := proto.Marshal(msg.Committed)
		if err != nil {
			glog.Warningf("proto.Marshal(): %v", err)
			mutationFailures.Inc(directoryID, "Marshal")
			continue
		}

		// Make sure that only ONE MapLeaf is output per index.
		retMap[string(e.Index)] = &tpb.MapLeaf{
			Index:     e.Index,
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

// HighWatermarks returns the total count across all logs and the highest watermark for each log.
// batchSize is a limit on the total number of items represented by the returned watermarks.
// TODO(gbelvin): Block until a minBatchSize has been reached or a timeout has occurred.
func (s *Server) HighWatermarks(ctx context.Context, directoryID string, starts Watermarks,
	batchSize int32) (int32, Watermarks, error) {
	watermarks := make(Watermarks)
	var total int32

	// Ensure that we do not lose track of watermarks, even if they are no
	// longer in the active log list, or if they do not move. The sequencer
	// needs them to know where to pick up reading for the next map
	// revision.
	// TODO(gbelvin): Separate high water marks for the sequencer's needs
	// from the verifier's needs.
	for logID, low := range starts {
		watermarks[logID] = low
	}

	filterForWritable := false
	logIDs, err := s.logs.ListLogs(ctx, directoryID, filterForWritable)
	if err != nil {
		return 0, nil, err
	}
	// TODO(gbelvin): Get HighWatermarks in parallel.
	for _, logID := range logIDs {
		start := starts[logID]
		if batchSize <= 0 {
			watermarks[logID] = start
			continue
		}
		count, high, err := s.logs.HighWatermark(ctx, directoryID, logID, start, batchSize)
		if err != nil {
			return 0, nil, status.Errorf(codes.Internal,
				"HighWatermark(%v/%v, start: %v, batch: %v): %v",
				directoryID, logID, start, batchSize, err)
		}
		watermarks[logID] = high
		total += count
		batchSize -= count
	}
	return total, watermarks, nil
}
