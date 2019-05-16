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

// Package runner executes the mapper pipeline.
package runner

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// IncMetricFn increments a metric
type IncMetricFn func(label string)

// Joined is the result of a CoGroupByKey on []*MapLeaf and []*IndexedValue.
type Joined struct {
	Index   []byte
	Values1 []*pb.EntryUpdate
	Values2 []*pb.EntryUpdate
}

func wrapErrFn(emitErr func(error), msg string) func(error) {
	return func(err error) {
		s := status.Convert(err)
		emitErr(status.Errorf(s.Code(), "%v: %v", msg, s.Message()))
	}
}

// Join pairs up MapLeaves and IndexedValue by index.
func Join(leaves []*entry.IndexedValue, msgs []*entry.IndexedValue, incFn IncMetricFn) <-chan *Joined {
	joinMap := make(map[string]*Joined)
	for _, l := range leaves {
		incFn("Join1")
		row, ok := joinMap[string(l.Index)]
		if !ok {
			row = &Joined{Index: l.Index}
		}
		row.Values1 = append(row.Values1, l.Value)
		joinMap[string(l.Index)] = row
	}
	for _, m := range msgs {
		incFn("Join2")
		row, ok := joinMap[string(m.Index)]
		if !ok {
			row = &Joined{Index: m.Index}
		}
		row.Values2 = append(row.Values2, m.Value)
		joinMap[string(m.Index)] = row
	}

	ret := make(chan *Joined)
	go func() {
		defer close(ret)
		for _, r := range joinMap {
			ret <- r
		}
	}()
	return ret
}

// MapMetaFn emits a source slice for every map slice.
type MapMetaFn func(meta *spb.MapMetadata, emit func(*spb.MapMetadata_SourceSlice))

// DoMapMetaFn runs MapMetaFn on meta and collects the outputs.
func DoMapMetaFn(fn MapMetaFn, meta *spb.MapMetadata, incFn IncMetricFn) []*spb.MapMetadata_SourceSlice {
	outs := make([]*spb.MapMetadata_SourceSlice, 0, len(meta.GetSources()))
	incFn("MapMetaFn")
	fn(meta, func(slice *spb.MapMetadata_SourceSlice) { outs = append(outs, slice) })
	return outs
}

// ReadSliceFn emits the log messages referenced by slice.
type ReadSliceFn func(ctx context.Context, slice *spb.MapMetadata_SourceSlice,
	directoryID string, chunkSize int32,
	emit func(*mutator.LogMessage)) error

// DoReadFn runs ReadSliceFn on every source slice and collects the outputs.
func DoReadFn(ctx context.Context, fn ReadSliceFn, slices []*spb.MapMetadata_SourceSlice,
	directoryID string, chunkSize int32, incFn IncMetricFn) ([]*mutator.LogMessage, error) {
	outs := make([]*mutator.LogMessage, 0, len(slices))
	for _, s := range slices {
		incFn("ReadSliceFn")
		if err := fn(ctx, s, directoryID, chunkSize,
			func(msg *mutator.LogMessage) { outs = append(outs, msg) },
		); err != nil {
			return nil, err
		}
	}
	return outs, nil
}

// MapLogItemFn takes a log item and emits 0 or more KV<index, mutations> pairs.
type MapLogItemFn func(logItem *mutator.LogMessage,
	emit func(index []byte, mutation *pb.EntryUpdate), emitErr func(error))

// DoMapLogItemsFn runs the MapLogItemsFn on each element of msgs.
func DoMapLogItemsFn(fn MapLogItemFn, msgs []*mutator.LogMessage,
	emitErr func(error), incFn IncMetricFn) []*entry.IndexedValue {
	outs := make([]*entry.IndexedValue, 0, len(msgs))
	for _, m := range msgs {
		incFn("MapLogItemFn")
		fn(m,
			func(index []byte, value *pb.EntryUpdate) {
				outs = append(outs, &entry.IndexedValue{Index: index, Value: value})
			},
			wrapErrFn(emitErr, "mapLogItemFn"),
		)
	}
	return outs
}

// MapMapLeafFn converts an update into an IndexedValue.
type MapMapLeafFn func(*tpb.MapLeaf) (*entry.IndexedValue, error)

// DoMapMapLeafFn runs MapMapLeafFn on each MapLeaf.
func DoMapMapLeafFn(fn MapMapLeafFn, leaves []*tpb.MapLeaf, incFn IncMetricFn) ([]*entry.IndexedValue, error) {
	outs := make([]*entry.IndexedValue, 0, len(leaves))
	for _, m := range leaves {
		incFn("MapMapLeafFn")
		out, err := fn(m)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}

// ReduceMutationFn takes all the mutations for an index and an auxiliary input
// of existing mapleaf(s) and emits a new value for the index.
// ReduceMutationFn must be  idempotent, commutative, and associative.  i.e.
// must produce the same output  regardless of input order or grouping,
// and it must be safe to run multiple times.
type ReduceMutationFn func(msgs []*pb.EntryUpdate, leaves []*pb.EntryUpdate,
	emit func(*pb.EntryUpdate), emitErr func(error))

// DoReduceFn takes the set of mutations and applies them to given leaves.
// Returns a channel of key value pairs that should be written to the map.
func DoReduceFn(reduceFn ReduceMutationFn, joined <-chan *Joined, emitErr func(error),
	incFn IncMetricFn) <-chan *entry.IndexedValue {
	ret := make(chan *entry.IndexedValue)
	go func() {
		defer close(ret)
		var wg sync.WaitGroup
		defer wg.Wait()
		// TODO(gbelvin): Configurable number of workers.
		for w := 0; w < runtime.NumCPU(); w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for j := range joined {
					incFn("ReduceFn")
					reduceFn(j.Values1, j.Values2,
						func(e *pb.EntryUpdate) {
							ret <- &entry.IndexedValue{Index: j.Index, Value: e}
						},
						wrapErrFn(emitErr, fmt.Sprintf("reduceFn on index %x", j.Index)),
					)
				}
			}()
		}
	}()
	return ret
}

// DoMarshalIndexedValues executes Marshal on each IndexedValue
// If marshal fails, it will emit an error and continue with a subset of ivs.
func DoMarshalIndexedValues(ivs <-chan *entry.IndexedValue, emitErr func(error), incFn IncMetricFn) []*tpb.MapLeaf {
	ret := make([]*tpb.MapLeaf, 0, len(ivs))
	for iv := range ivs {
		incFn("MarshalIndexedValue")
		mapLeaf, err := iv.Marshal()
		if err != nil {
			emitErr(status.Errorf(codes.Internal, "MarshalIndexedValue(): %v", err))
			continue
		}
		ret = append(ret, mapLeaf)
	}
	return ret
}
