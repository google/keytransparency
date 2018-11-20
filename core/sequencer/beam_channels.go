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

	"github.com/golang/glog"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

type logSource struct {
	LogID  int64
	Source *spb.MapMetadata_SourceSlice
}

type indexMutation struct {
	index    []byte
	mutation *ktpb.EntryUpdate
}

type indexLeaf struct {
	index []byte
	leaf  *tpb.MapLeaf
}

type joinRow struct {
	index  []byte
	leaves []*tpb.MapLeaf
	msgs   []*ktpb.EntryUpdate
}

// MapWriter writes to the trillian Map.
type MapWriter interface {
	// WriteMap sends leaves to the map for directoryID.
	WriteMap(ctx context.Context, leaves []*tpb.MapLeaf, meta *spb.MapMetadata, directoryID string) error
}

// MapReader reads a set of indexes from the map.
// TODO(gbelivn): Read at a specific map revision.
type MapReader interface {
	// ReadMap emits one map leaf for every index requested.
	ReadMap(ctx context.Context, indexes [][]byte, directoryID string,
		emit func(index []byte, leaf *tpb.MapLeaf)) error
}

// LogReader reads log items from a log.
type LogReader interface {
	// ReadLog calls emit for every item in the log.
	ReadLog(ctx context.Context, logID int64, source *spb.MapMetadata_SourceSlice,
		directoryID string, batchSize int32, emit func(*ktpb.EntryUpdate)) error
}

// CreateRevisionWithChannels is an implementation of CreateRev without using beam.
func CreateRevisionWithChannels(ctx context.Context, dirID string, rev int64,
	meta *spb.MapMetadata, batchSize int32,
	mw MapWriter, mr MapReader, lr LogReader) error {
	// Read each logID in parallel.
	logSources := goSplitMeta(meta)
	logItems := goReadLog(ctx, logSources, dirID, batchSize, lr)
	keyedMutations := goMapLogItems(logItems)
	keyedMutations1, keyedMutations2 := goTeeMutations(keyedMutations)

	// Read the map.
	allIndexes := goCombineIndexes(goDropValue(keyedMutations1))
	mapLeaves := goReadMap(ctx, allIndexes, dirID, mr)

	// Join mutations and map leaves.
	joined := goJoin(mapLeaves, keyedMutations2)

	// Apply user defined mutation function.
	newMapLeaves := goApply(joined)

	// Write to map.
	allMapLeaves := goCombineMapLeaves(newMapLeaves)
	return goWriteMap(ctx, allMapLeaves, meta, dirID, mw)
}

func goSplitMeta(meta *spb.MapMetadata) <-chan logSource {
	metaChan := make(chan logSource)
	go func() {
		splitMeta(meta, func(logID int64, source *spb.MapMetadata_SourceSlice) {
			ls := logSource{LogID: logID, Source: source}
			glog.V(2).Infof("LogSource: %v", ls)
			metaChan <- ls
		})
		close(metaChan)
	}()
	return metaChan
}

func goReadLog(ctx context.Context, logs <-chan logSource, dirID string, batchSize int32,
	lr LogReader) <-chan *ktpb.EntryUpdate {
	entries := make(chan *ktpb.EntryUpdate)
	go func() {
		var wg sync.WaitGroup
		for l := range logs {
			wg.Add(1)
			// Read each log in parallel.
			go func(l logSource) {
				if err := lr.ReadLog(ctx, l.LogID, l.Source, dirID, batchSize,
					func(e *ktpb.EntryUpdate) {
						glog.V(2).Infof("LogItem: %v", e)
						entries <- e
					}); err != nil {
					close(entries)
				}
				wg.Done()
			}(l)
		}
		wg.Wait() // Wait for reads to finish
		close(entries)
	}()
	return entries
}

func goMapLogItems(logItems <-chan *ktpb.EntryUpdate) <-chan indexMutation {
	c := make(chan indexMutation)
	go func() {
		for e := range logItems {
			mapLogItem(e, func(index []byte, update *ktpb.EntryUpdate) {
				glog.V(2).Infof("LogKV: <%x: _>", index)
				c <- indexMutation{index: index, mutation: update}
			})
		}
		close(c)
	}()
	return c
}

func goTeeMutations(mutations <-chan indexMutation) (<-chan indexMutation, <-chan indexMutation) {
	c1 := make(chan indexMutation)
	c2 := make(chan indexMutation)
	go func() {
		for e := range mutations {
			c1 <- e
			c2 <- e
		}
		close(c1)
		close(c2)
	}()
	return c1, c2
}

func goDropValue(mutations <-chan indexMutation) <-chan []byte {
	c := make(chan []byte)
	go func() {
		for e := range mutations {
			glog.V(2).Infof("Index: %x", e.index)
			c <- e.index
		}
		close(c)
	}()
	return c
}

func goCombineIndexes(indexes <-chan []byte) <-chan [][]byte {
	c := make(chan [][]byte)
	mergeFn := &mergeIndexFn{}
	go func() {
		accum := mergeFn.CreateAccumulator()
		for i := range indexes {
			accum = mergeFn.AddInput(accum, i)
		}
		c <- mergeFn.ExtractOutput(accum)
		close(c)
	}()
	return c
}

func goReadMap(ctx context.Context, indexSets <-chan [][]byte, dirID string, mr MapReader) <-chan indexLeaf {
	c := make(chan indexLeaf)
	go func() {
		// There should only be one index set.
		for indexes := range indexSets {
			if err := mr.ReadMap(ctx, indexes, dirID, func(index []byte, leaf *tpb.MapLeaf) {
				glog.V(2).Infof("ReadMapKV: <%x, %v>", index, leaf)
				c <- indexLeaf{index: index, leaf: leaf}
			}); err != nil {
				glog.Errorf("ReadMap failed: %v", err)
			}
		}
		close(c)
	}()
	return c
}

func goJoin(leaves <-chan indexLeaf, msgs <-chan indexMutation) <-chan joinRow {
	leafMap := make(map[string][]*tpb.MapLeaf)
	msgMap := make(map[string][]*ktpb.EntryUpdate)
	c := make(chan joinRow)
	go func() {
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			for l := range leaves {
				existing := leafMap[string(l.index)]
				leafMap[string(l.index)] = append(existing, l.leaf)
			}
			wg.Done()
		}()
		go func() {
			for l := range msgs {
				existing := msgMap[string(l.index)]
				msgMap[string(l.index)] = append(existing, l.mutation)
			}
			wg.Done()
		}()
		wg.Wait() // Wait for all indexes and mutations to be collected.
		for i, msgs := range msgMap {
			glog.V(2).Infof("JoinedRow: <%x, %v, %v>", []byte(i), leafMap[i], msgs)
			c <- joinRow{index: []byte(i), leaves: leafMap[i], msgs: msgs}
		}
		close(c)
	}()
	return c
}

func goApply(rows <-chan joinRow) <-chan *tpb.MapLeaf {
	c := make(chan *tpb.MapLeaf)
	go func() {
		for r := range rows {
			if err := applyMutation(r.index,
				mapLeafIterator(r.leaves), entryUpdateIterator(r.msgs),
				func(l *tpb.MapLeaf) {
					glog.V(2).Infof("NewMapLeaf: %v", l)
					c <- l
				}); err != nil {
				glog.Warningf("applyMutation failed: %v", err)
			}
		}
		close(c)
	}()
	return c
}

func mapLeafIterator(leaves []*tpb.MapLeaf) func(e **tpb.MapLeaf) bool {
	var leafIndex int
	return func(e **tpb.MapLeaf) bool {
		if leafIndex < len(leaves) {
			*e = leaves[leafIndex]
			leafIndex++
			return true
		}
		return false
	}
}

func entryUpdateIterator(msgs []*ktpb.EntryUpdate) func(e **ktpb.EntryUpdate) bool {
	var msgIndex int
	return func(e **ktpb.EntryUpdate) bool {
		if msgIndex < len(msgs) {
			*e = msgs[msgIndex]
			msgIndex++
			return true
		}
		return false
	}
}

func goCombineMapLeaves(leaves <-chan *tpb.MapLeaf) <-chan []*tpb.MapLeaf {
	c := make(chan []*tpb.MapLeaf)
	mergeFn := &mergeMapLeavesFn{}
	go func() {
		accum := mergeFn.CreateAccumulator()
		for l := range leaves {
			accum = mergeFn.AddInput(accum, l)
		}
		c <- mergeFn.ExtractOutput(accum)
		close(c)
	}()
	return c
}

func goWriteMap(ctx context.Context, leafSets <-chan []*tpb.MapLeaf,
	meta *spb.MapMetadata, dirID string, mw MapWriter) error {
	// There should only be one leafSet.
	for leaves := range leafSets {
		if err := mw.WriteMap(ctx, leaves, meta, dirID); err != nil {
			return err
		}
	}
	return nil
}
