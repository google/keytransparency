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

func (s *Server) createRevision(ctx context.Context,
	in *spb.CreateRevisionRequest, meta *spb.MapMetadata) error {
	readBatchSize := int32(1000) // TODO(gbelvin): Make configurable.

	// Read eac logID in parallel.
	logSources := goSplitMeta(meta)
	logItems := s.goReadOneLog(ctx, logSources, in.DirectoryId, readBatchSize)
	keyedMutations := goMapLogItems(logItems)
	keyedMutations1, keyedMutations2 := goTeeMutations(keyedMutations)

	// Read the map.
	allIndexes := goCombineIndexes(goDropValue(keyedMutations1))
	mapLeaves := s.goReadMap(ctx, allIndexes, in.DirectoryId)

	// Join mutations and map leaves.
	joined := goJoin(mapLeaves, keyedMutations2)
	newMapLeaves := goApply(joined)

	// Write to map.
	allMapLeaves := goCombineMapLeaves(newMapLeaves)
	return s.goWriteMap(ctx, allMapLeaves, meta, in.DirectoryId)
}

func goSplitMeta(meta *spb.MapMetadata) <-chan logSource {
	metaChan := make(chan logSource)
	go func() {
		splitMeta(meta, func(logID int64, source *spb.MapMetadata_SourceSlice) {
			metaChan <- logSource{LogID: logID, Source: source}
		})
		close(metaChan)
	}()
	return metaChan
}

func (s *Server) goReadOneLog(ctx context.Context, logs <-chan logSource, dirID string, batchSize int32) <-chan *ktpb.EntryUpdate {
	entries := make(chan *ktpb.EntryUpdate)
	go func() {
		var wg sync.WaitGroup
		for l := range logs {
			wg.Add(1)
			// Read each log in parallel.
			go func(l logSource) {
				if err := s.readOneLog(ctx, l.LogID, l.Source, dirID, batchSize,
					func(e *ktpb.EntryUpdate) { entries <- e }); err != nil {
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

func (s *Server) goReadMap(ctx context.Context, indexSets <-chan [][]byte, dirID string) <-chan indexLeaf {
	c := make(chan indexLeaf)
	go func() {
		// There should only be one index set.
		for indexes := range indexSets {
			s.readMap(ctx, indexes, dirID, func(index []byte, leaf *tpb.MapLeaf) {
				c <- indexLeaf{index: index, leaf: leaf}
			})
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
			var leafIndex int
			var msgIndex int
			applyMutation(r.index,
				func(e **tpb.MapLeaf) bool {
					*e = r.leaves[leafIndex]
					leafIndex++
					return leafIndex < len(r.leaves)
				},
				func(e **ktpb.EntryUpdate) bool {
					*e = r.msgs[msgIndex]
					msgIndex++
					return msgIndex < len(r.msgs)
				},
				func(l *tpb.MapLeaf) {
					c <- l
				})
		}
		close(c)
	}()
	return c
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

// Sink all existing chanels.
func (s *Server) goWriteMap(ctx context.Context, leafSets <-chan []*tpb.MapLeaf, meta *spb.MapMetadata, dirID string) error {
	// There should only be one leafSet.
	for leaves := range leafSets {
		if err := s.writeMap(ctx, leaves, meta, dirID); err != nil {
			return err
		}
	}
	return nil
}
