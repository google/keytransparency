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
	"fmt"
	"sort"
	"sync"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/trillian/monitoring"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer/runner"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

const (
	directoryIDLabel = "directoryid"
	logIDLabel       = "logid"
	reasonLabel      = "reason"
)

var (
	initMetrics      sync.Once
	knownDirectories monitoring.Gauge
	logEntryCount    monitoring.Counter
	mapLeafCount     monitoring.Counter
	mapRevisionCount monitoring.Counter
	watermarkDefined monitoring.Gauge
	watermarkApplied monitoring.Gauge
	mutationFailures monitoring.Counter
)

func createMetrics(mf monitoring.MetricFactory) {
	knownDirectories = mf.NewGauge(
		"known_directories",
		"Set to 1 for known directories (whether this instance is master or not)",
		directoryIDLabel)
	logEntryCount = mf.NewCounter(
		"log_entry_count",
		"Total number of log entries read since process start. Duplicates are not removed.",
		directoryIDLabel, logIDLabel)
	mapLeafCount = mf.NewCounter(
		"map_leaf_count",
		"Total number of map leaves written since process start. Duplicates are not removed.",
		directoryIDLabel)
	mapRevisionCount = mf.NewCounter(
		"map_revision_count",
		"Total number of map revisions written since process start.",
		directoryIDLabel)
	watermarkDefined = mf.NewGauge(
		"watermark_defined",
		"High watermark of each input log that has been defined in the batch table",
		directoryIDLabel, logIDLabel)
	watermarkApplied = mf.NewGauge(
		"watermark_applied",
		"High watermark of each input log that has been committed in a map revision",
		directoryIDLabel, logIDLabel)
	mutationFailures = mf.NewCounter(
		"mutation_failures",
		"Number of invalid mutations the signer has processed for directoryid since process start",
		directoryIDLabel, reasonLabel)
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
	batcher   Batcher
	trillian  trillianFactory
	logs      LogsReader
	loopback  spb.KeyTransparencySequencerClient
	BatchSize int32
}

// NewServer creates a new KeyTransparencySequencerServer.
func NewServer(
	directories directory.Storage,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	batcher Batcher,
	logs LogsReader,
	loopback spb.KeyTransparencySequencerClient,
	metricsFactory monitoring.MetricFactory,
) *Server {
	initMetrics.Do(func() { createMetrics(metricsFactory) })
	return &Server{
		trillian: &Trillian{
			directories: directories,
			tmap:        tmap,
			tlog:        tlog,
		},
		batcher:   batcher,
		logs:      logs,
		loopback:  loopback,
		BatchSize: 10000,
	}
}

// RunBatch runs the full sequence of steps (for one directory) nessesary to get a
// mutation from the log integrated into the map. This consists of a series of
// idempotent steps:
// a) assign a batch of mutations from the logs to a map revision
// b) apply the batch to the map
// c) publish existing map roots to a log of SignedMapRoots.
func (s *Server) RunBatch(ctx context.Context, in *spb.RunBatchRequest) (*empty.Empty, error) {
	defResp, err := s.loopback.DefineRevisions(ctx, &spb.DefineRevisionsRequest{
		DirectoryId: in.DirectoryId,
		MinBatch:    in.MinBatch,
		MaxBatch:    in.MaxBatch})
	if err != nil {
		return nil, err
	}

	for _, rev := range defResp.OutstandingRevisions {
		if _, err := s.loopback.ApplyRevision(ctx, &spb.ApplyRevisionRequest{
			DirectoryId: in.DirectoryId,
			Revision:    rev,
		}); err != nil {
			// Log the error and continue to publish any revsisions this run may have completed.
			// This revision will be retried on the next execution of RunBatch.
			glog.Errorf("ApplyRevision(dir: %v, rev: %v): %v", in.DirectoryId, rev, err)
			break
		}
	}

	publishReq := &spb.PublishRevisionsRequest{DirectoryId: in.DirectoryId, Block: in.Block}
	_, err = s.loopback.PublishRevisions(ctx, publishReq)
	if err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}

// DefineRevisions examines the outstanding mutations and returns a list of
// outstanding revisions that have not been applied.
func (s *Server) DefineRevisions(ctx context.Context,
	in *spb.DefineRevisionsRequest) (*spb.DefineRevisionsResponse, error) {
	// Get the previous and current high water marks.
	mapClient, err := s.trillian.MapClient(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}
	_, latestMapRoot, err := mapClient.GetAndVerifyLatestMapRoot(ctx)
	if err != nil {
		return nil, err
	}

	// Collect a list of unapplied revisions.
	highestRev, err := s.batcher.HighestRev(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}
	outstanding := []int64{}
	for rev := int64(latestMapRoot.Revision) + 1; rev <= highestRev; rev++ {
		outstanding = append(outstanding, rev)
	}

	// Don't create new revisions if there are ones waiting to be applied.
	if len(outstanding) > 0 {
		return &spb.DefineRevisionsResponse{OutstandingRevisions: outstanding}, nil
	}

	// Query metadata about outstanding log items.
	var lastMeta spb.MapMetadata
	if err := proto.Unmarshal(latestMapRoot.Metadata, &lastMeta); err != nil {
		return nil, err
	}

	count, meta, err := s.HighWatermarks(ctx, in.DirectoryId, &lastMeta, in.MaxBatch)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "HighWatermarks(): %v", err)
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
			return nil, err
		}
		for _, source := range meta.Sources {
			watermarkDefined.Set(float64(source.HighestExclusive),
				in.DirectoryId, fmt.Sprintf("%v", source.LogId))
		}
		outstanding = append(outstanding, nextRev)

	}
	// TODO(#1056): If count items == max_batch, should we define the next batch immediately?

	return &spb.DefineRevisionsResponse{OutstandingRevisions: outstanding}, nil
}

// readMessages returns the full set of EntryUpdates defined by sources.
// batchSize limits the number of messages to read from a log at one time.
func (s *Server) readMessages(ctx context.Context, directoryID string, meta *spb.MapMetadata,
	batchSize int32) ([]*mutator.LogMessage, error) {
	msgs := make([]*mutator.LogMessage, 0)
	for _, source := range meta.Sources {
		low := source.LowestInclusive
		high := source.HighestExclusive
		// Loop until less than batchSize items are returned.
		for count := batchSize; count == batchSize; {
			batch, err := s.logs.ReadLog(ctx, directoryID, source.LogId, low, high, batchSize)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "ReadLog(): %v", err)
			}
			count = int32(len(batch))
			glog.Infof("ReadLog(dir: %v log: %v, (%v, %v], %v) count: %v",
				directoryID, source.LogId, low, high, batchSize, count)
			logEntryCount.Add(float64(len(batch)), directoryID, fmt.Sprintf("%v", source.LogId))
			for _, m := range batch {
				msgs = append(msgs, m)
				if m.ID > low {
					low = m.ID
				}
			}
		}
	}
	return msgs, nil
}

// ApplyRevision applies the supplied mutations to the current map revision and creates a new revision.
func (s *Server) ApplyRevision(ctx context.Context, in *spb.ApplyRevisionRequest) (*spb.ApplyRevisionResponse, error) {
	meta, err := s.batcher.ReadBatch(ctx, in.DirectoryId, in.Revision)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "ReadBatch(%v, %v): %v", in.DirectoryId, in.Revision, err)
	}
	glog.Infof("ApplyRevision(): dir: %v, rev: %v, sources: %v", in.DirectoryId, in.Revision, meta)
	msgs, err := s.readMessages(ctx, in.DirectoryId, meta, s.BatchSize)
	if err != nil {
		return nil, err
	}

	// Map Log Items
	indexedValues := runner.DoMapLogItemsFn(entry.MapLogItemFn, msgs,
		func(err error) { glog.Warning(err); mutationFailures.Inc(err.Error()) },
	)

	// Collect Indexes.
	indexes := make([][]byte, 0, len(indexedValues))
	for _, iv := range indexedValues {
		indexes = append(indexes, iv.Index)
	}

	// Read Map.
	mapClient, err := s.trillian.MapClient(ctx, in.DirectoryId)
	if err != nil {
		return nil, err
	}
	leaves, err := mapClient.GetAndVerifyMapLeavesByRevision(ctx, in.Revision-1, indexes)
	if err != nil {
		return nil, err
	}

	// Apply mutations to values.
	newLeaves, err := runner.ApplyMutations(entry.ReduceFn, indexedValues, leaves,
		func(err error) { glog.Warning(err); mutationFailures.Inc(err.Error()) },
	)
	if err != nil {
		return nil, err
	}

	// Serialize metadata
	metadata, err := proto.Marshal(meta)
	if err != nil {
		return nil, err
	}

	// Set new leaf values.
	mapRoot, err := mapClient.SetLeavesAtRevision(ctx, in.Revision, newLeaves, metadata)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "VerifySignedMapRoot(): %v", err)
	}
	glog.V(2).Infof("CreateRevision: SetLeaves:{Revision: %v}", mapRoot.Revision)

	for _, s := range meta.Sources {
		watermarkApplied.Set(float64(s.HighestExclusive),
			in.DirectoryId, fmt.Sprintf("%v", s.LogId))
	}
	mapLeafCount.Add(float64(len(newLeaves)), in.DirectoryId)
	mapRevisionCount.Add(1, in.DirectoryId)
	glog.Infof("ApplyRevision(): dir: %v, rev: %v, root: %x, mutations: %v, indexes: %v, newleaves: %v",
		in.DirectoryId, mapRoot.Revision, mapRoot.RootHash, len(msgs), len(indexes), len(newLeaves))
	return &spb.ApplyRevisionResponse{
		DirectoryId: in.DirectoryId,
		Revision:    in.Revision,
		Mutations:   int64(len(indexedValues)),
		MapLeaves:   int64(len(newLeaves)),
	}, nil
}

// PublishRevisions copies the MapRoots of all known map revisions into the Log of MapRoots.
func (s *Server) PublishRevisions(ctx context.Context,
	in *spb.PublishRevisionsRequest) (*spb.PublishRevisionsResponse, error) {
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
	revs := []int64{}
	leaves := make(map[int64][]byte)
	for rev := logRoot.TreeSize - 1; rev <= latestMapRoot.Revision; rev++ {
		rawMapRoot, mapRoot, err := mapClient.GetAndVerifyMapRootByRevision(ctx, int64(rev))
		if err != nil {
			return nil, err
		}
		leaves[int64(mapRoot.Revision)] = rawMapRoot.GetMapRoot()
		revs = append(revs, int64(mapRoot.Revision))
	}
	if err := logClient.AddSequencedLeaves(ctx, leaves); err != nil {
		glog.Errorf("AddSequencedLeaves(revs: %v): %v", revs, err)
		return nil, err
	}

	if in.Block {
		if err := logClient.WaitForInclusion(ctx, latestRawMapRoot.GetMapRoot()); err != nil {
			return nil, status.Errorf(codes.Internal, "WaitForInclusion(): %v", err)
		}
	}
	return &spb.PublishRevisionsResponse{Revisions: revs}, nil
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
		if ends[source.LogId] < source.HighestExclusive {
			ends[source.LogId] = source.HighestExclusive
			starts[source.LogId] = source.HighestExclusive
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
			LowestInclusive:  starts[logID],
			HighestExclusive: end,
		})
	}
	// Deterministic results are nice.
	sort.Slice(meta.Sources, func(a, b int) bool {
		return meta.Sources[a].LogId < meta.Sources[b].LogId
	})
	return total, meta, nil
}
