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
	"sort"
	"sync"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/trillian/monitoring"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
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
	// HighestRev returns the highest defined revision number for directoryID.
	HighestRev(ctx context.Context, directoryID string) (int64, error)
}

// Server implements KeyTransparencySequencerServer.
type Server struct {
	batcher  Batcher
	trillian TrillianFactory
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
		trillian: &Trillian{
			directories: directories,
			logAdmin:    logAdmin,
			mapAdmin:    mapAdmin,
			tmap:        tmap,
			tlog:        tlog,
		},
		batcher: batcher,
		logs:    logs,
	}
}

// RunBatch runs the full sequence of steps (for one directory) nessesary to get a
// mutation from the log integrated into the map. This consists of a series of
// idempotent steps:
// a) assign a batch of mutations from the logs to a map revision
// b) apply the batch to the map
// c) publish existing map roots to a log of SignedMapRoots.
func (s *Server) RunBatch(ctx context.Context, in *spb.RunBatchRequest) (*empty.Empty, error) {
	outstandingRevs, err := s.DefineRevisions(ctx, in.DirectoryId, in.MinBatch, in.MaxBatch)
	if err != nil {
		return nil, err
	}

	for _, rev := range outstandingRevs {
		if _, err := s.CreateRevision(ctx, &spb.CreateRevisionRequest{
			DirectoryId: in.DirectoryId,
			Revision:    rev,
		}); err != nil {
			return nil, err
		}
	}
	return &empty.Empty{}, nil
}

// DefineRevisions examines the outstanding mutations and returns a list of
// outstanding revisions that have not been applied.
func (s *Server) DefineRevisions(ctx context.Context, dirID string, minBatch, maxBatch int32) ([]int64, error) {
	// Get the previous and current high water marks.
	mapClient, err := s.trillian.MapClient(ctx, dirID)
	if err != nil {
		return nil, err
	}
	_, latestMapRoot, err := mapClient.GetAndVerifyLatestMapRoot(ctx)
	if err != nil {
		return nil, err
	}

	// Collect a list of unapplied revisions.
	outstanding := []int64{}
	highestRev, err := s.batcher.HighestRev(ctx, dirID)
	if err != nil {
		return nil, err
	}
	for rev := int64(latestMapRoot.Revision) + 1; rev <= highestRev; rev++ {
		outstanding = append(outstanding, rev)
	}

	// Don't create new revisions if there are ones waiting to be applied.
	if len(outstanding) > 0 {
		return outstanding, nil
	}

	// Query metadata about outstanding mutations.
	var lastMeta spb.MapMetadata
	if err := proto.Unmarshal(latestMapRoot.Metadata, &lastMeta); err != nil {
		return nil, err
	}

	count, meta, err := s.HighWatermarks(ctx, dirID, &lastMeta, maxBatch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "HighWatermarks(): %v", err)
	}

	//
	// Rate limit the creation of new batches.
	//

	// TODO(#1057): If time since last map revision > max timeout, define batch.
	// TODO(#1047): If time since oldest queue item > max latency has elapsed, define batch.
	// If count items >= min_batch, define batch.
	if count >= minBatch {
		nextRev := int64(latestMapRoot.Revision) + 1
		if err := s.batcher.WriteBatchSources(ctx, dirID, nextRev, meta); err != nil {
			return nil, err
		}
		outstanding = append(outstanding, nextRev)

	}
	// TODO(#1056): If count items == max_batch, should we define the next batch immediately?

	return outstanding, nil
}

// readMessages returns the full set of EntryUpdates defined by sources.
// batchSize limits the number of messages to read from a log at one time.
func (s *Server) readMessages(ctx context.Context, directoryID string, meta *spb.MapMetadata,
	batchSize int32) ([]*mutator.LogMessage, error) {
	msgs := make([]*mutator.LogMessage, 0)
	for _, source := range meta.Sources {
		low := source.GetLowestWatermark()
		high := source.GetHighestWatermark()
		// Loop until less than batchSize items are returned.
		for count := batchSize; count == batchSize; {
			batch, err := s.logs.ReadLog(ctx, directoryID, source.LogId, low, high, batchSize)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "ReadLog(): %v", err)
			}
			for _, m := range batch {
				msgs = append(msgs, m)
				if m.ID > low {
					low = m.ID
				}
			}
			count = int32(len(batch))
			glog.Infof("ReadLog(%v, (%v, %v], %v) count: %v", source.LogId, low, high, batchSize, count)
		}
	}
	return msgs, nil
}

// CreateRevision applies the supplied mutations to the current map revision and creates a new revision.
func (s *Server) CreateRevision(ctx context.Context, in *spb.CreateRevisionRequest) (*empty.Empty, error) {
	directoryID := in.GetDirectoryId()
	meta, err := s.batcher.ReadBatch(ctx, in.DirectoryId, in.Revision)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ReadBatch(%v, %v): %v", in.DirectoryId, in.Revision, err)
	}
	readBatchSize := int32(1000) // TODO(gbelvin): Make configurable.
	msgs, err := s.readMessages(ctx, in.DirectoryId, meta, readBatchSize)
	if err != nil {
		return nil, err
	}
	glog.Infof("CreateRevision: for %v with %d messages", directoryID, len(msgs))

	mapClient, err := s.trillian.MapClient(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}

	// Parse mutations using the mutator for this directory.
	batchSize.Set(float64(len(msgs)), in.DirectoryId)
	indexes := make([][]byte, 0, len(msgs))
	mutations := make([]*ktpb.EntryUpdate, 0, len(msgs))
	for _, m := range msgs {
		if err := entry.MapLogItemFn(m, func(index []byte, mutation *ktpb.EntryUpdate) {
			indexes = append(indexes, index)
			mutations = append(mutations, mutation)
		}); err != nil {
			return nil, err
		}

	}
	glog.V(2).Infof("CreateRevision: %v mutations, %v indexes", len(msgs), len(indexes))

	leaves, err := mapClient.GetAndVerifyMapLeavesByRevision(ctx, in.Revision-1, indexes)
	if err != nil {
		return nil, err
	}

	// Apply mutations to values.
	newLeaves, err := s.applyMutations(directoryID, entry.MutateFn, mutations, leaves)
	if err != nil {
		return nil, err
	}

	// Serialize metadata
	metadata, err := proto.Marshal(meta)
	if err != nil {
		return nil, err
	}

	// Set new leaf values.
	mapRoot, err := mapClient.SetLeaves(ctx, newLeaves, metadata)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	glog.V(2).Infof("CreateRevision: SetLeaves:{Revision: %v}", mapRoot.Revision)

	mutationCount.Add(float64(len(msgs)), directoryID)
	glog.Infof("CreatedRevision: rev: %v with %v mutations, root: %x", mapRoot.Revision, len(msgs), mapRoot.RootHash)
	return s.PublishBatch(ctx, &spb.PublishBatchRequest{DirectoryId: directoryID})
}

// PublishBatch copies the MapRoots of all known map revisions into the Log of MapRoots.
func (s *Server) PublishBatch(ctx context.Context, in *spb.PublishBatchRequest) (*empty.Empty, error) {
	// Create verifying log and map clients.
	logClient, err := s.trillian.LogClient(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}
	mapClient, err := s.trillian.MapClient(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}

	// Get latest log root and map root.
	logRoot, err := logClient.UpdateRoot(ctx)
	if err != nil {
		return nil, err
	}
	latestRawMapRoot, latestMapRoot, err := mapClient.GetAndVerifyLatestMapRoot(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "GetAndVerifyLatestMapRoot(): %v", err)
	}

	// Add all unpublished map roots to the log.
	for rev := logRoot.TreeSize - 1; rev <= latestMapRoot.Revision; rev++ {
		rawMapRoot, mapRoot, err := mapClient.GetAndVerifyMapRootByRevision(ctx, int64(rev))
		if err != nil {
			return nil, err
		}
		if err := logClient.AddSequencedLeaf(ctx, rawMapRoot.GetMapRoot(), int64(mapRoot.Revision)); err != nil {
			glog.Errorf("AddSequencedLeaf(rev: %v): %v", mapRoot.Revision, err)
			return nil, err
		}
	}
	// TODO(gbelvin): Remove wait when batching boundaries are deterministic.
	if err := logClient.WaitForInclusion(ctx, latestRawMapRoot.GetMapRoot()); err != nil {
		return nil, status.Errorf(codes.Internal, "WaitForInclusion(): %v", err)
	}
	return &empty.Empty{}, nil
}

// applyMutations takes the set of mutations and applies them to given leafs.
// Multiple mutations for the same leaf will be applied to provided leaf.
// The last valid mutation for each leaf is included in the output.
// Returns a list of map leaves that should be updated.
func (s *Server) applyMutations(directoryID string, mutatorFunc mutator.ReduceMutationFn,
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

		newValue, err := mutatorFunc(oldValue, msg.Mutation)
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
func (s *Server) HighWatermarks(ctx context.Context, directoryID string, lastMeta *spb.MapMetadata,
	batchSize int32) (int32, *spb.MapMetadata, error) {
	var total int32

	// Ensure that we do not lose track of end watermarks, even if they are no
	// longer in the active log list, or if they do not move. The sequencer
	// needs them to know where to pick up reading for the next map
	// revision.
	// TODO(gbelvin): Separate end watermarks for the sequencer's needs
	// from ranges of watermarks for the verifier's needs.
	ends := map[int64]int64{}
	starts := map[int64]int64{}
	for _, source := range lastMeta.Sources {
		if ends[source.LogId] < source.HighestWatermark {
			ends[source.LogId] = source.HighestWatermark
			starts[source.LogId] = source.HighestWatermark
		}
	}

	filterForWritable := false
	logIDs, err := s.logs.ListLogs(ctx, directoryID, filterForWritable)
	if err != nil {
		return 0, nil, err
	}
	// TODO(gbelvin): Get HighWatermarks in parallel.
	for _, logID := range logIDs {
		low := ends[logID]
		count, high, err := s.logs.HighWatermark(ctx, directoryID, logID, low, batchSize)
		if err != nil {
			return 0, nil, status.Errorf(codes.Internal,
				"HighWatermark(%v/%v, start: %v, batch: %v): %v",
				directoryID, logID, low, batchSize, err)
		}
		starts[logID], ends[logID] = low, high
		total += count
		batchSize -= count
	}

	meta := &spb.MapMetadata{}
	for logID, end := range ends {
		meta.Sources = append(meta.Sources, &spb.MapMetadata_SourceSlice{
			LogId:            logID,
			LowestWatermark:  starts[logID],
			HighestWatermark: end,
		})
	}
	// Deterministic results are nice.
	sort.Slice(meta.Sources, func(a, b int) bool {
		return meta.Sources[a].LogId < meta.Sources[b].LogId
	})
	return total, meta, nil
}
