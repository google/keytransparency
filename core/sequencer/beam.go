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

// To exclude beam dependencies run go with --tag nobeam.
// +build !nobeam

package sequencer

import (
	"context"

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// CreateRevisionWithBeam is an implementation of CreateRevFn using beam.
func CreateRevisionWithBeam(ctx context.Context, directoryID string, rev int64,
	metaProto *spb.MapMetadata, batchSize int32,
	mw MapWriter, mr MapReader, lr LogReader) error {

	p := beam.NewPipeline()
	scope := p.Root()

	meta := beam.Create(scope, metaProto)
	dirID := beam.Create(scope, directoryID)
	// Read each logID in parallel.
	sourceSlices := beam.ParDo(scope, splitMeta, meta) // KV<logID, source>
	logItems := beam.ParDo(scope, lr.ReadLog, sourceSlices,
		beam.SideInput{Input: dirID},
		beam.SideInput{Input: beam.Create(scope, batchSize)}) // *ktpb.EntryUpdate

	keyedMutations := beam.ParDo(scope, mapLogItem, logItems) // KV<index, *ktpb.EntryUpdate>

	// Read the map
	indexes := beam.Combine(scope, &mergeIndexFn{}, beam.DropValue(scope, keyedMutations)) // []index
	mapLeaves := beam.ParDo(scope, mr.ReadMap, indexes, beam.SideInput{Input: dirID})      // KV<index, *tpb.MapLeaf>

	// Align MapLeaves with their mutations and apply mutations.
	joined := beam.CoGroupByKey(scope, mapLeaves, keyedMutations) // []*tpb.MapLeaf, []*ktpb.EntryUpdate
	newMapLeaves := beam.ParDo(scope, applyMutation, joined)      // *tpb.MapLeaf

	// Write to map.
	beam.ParDo0(scope, mw.WriteMap,
		collectMapLeaves(scope, newMapLeaves),
		beam.SideInput{Input: meta},
		beam.SideInput{Input: dirID})

	return beamx.Run(ctx, p)
}

// collectMapLeaves returns a collection with a single element of []*tpb.MapLeaf
// collectMapLeaves always returns a PCollection with a single element, even if there are no elements in c.
func collectMapLeaves(s beam.Scope, mapLeaves beam.PCollection) beam.PCollection {
	s = s.Scope("collectMapLeaves")
	allLeaves := beam.Combine(s, &mergeMapLeavesFn{}, mapLeaves)
	emptyList := beam.Create(s, []*tpb.MapLeaf{})
	twoLists := beam.Flatten(s, allLeaves, emptyList)

	// Combine with an empty PCollection to ensure that the output PCollection is not empty.
	return beam.Combine(s, MergeMapLeaves, twoLists)
}

// MergeMapLeaves takes two MapLeaves and combines them.
func MergeMapLeaves(a, b MapLeaves) MapLeaves {
	return append(a, b...)
}
