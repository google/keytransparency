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
	"github.com/golang/glog"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer/mapper"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// ApplyMutations takes the set of mutations and applies them to given leaves.
// Returns a list of map leaves that should be updated.
func ApplyMutations(reduceFn mutator.ReduceMutationFn,
	msgs []*pb.EntryUpdate, leaves []*tpb.MapLeaf, emitErr func(error)) ([]*tpb.MapLeaf, error) {
	// Index the updates.
	indexedUpdates, err := DoMapUpdateFn(mapper.MapUpdateFn, msgs)
	if err != nil {
		return nil, err
	}

	indexedLeaves, err := DoMapMapLeafFn(mapper.MapMapLeafFn, leaves)
	if err != nil {
		return nil, err
	}

	joined := Join(indexedLeaves, indexedUpdates)

	ret := make([]*tpb.MapLeaf, 0, len(joined))
	for _, j := range joined {
		reduceFn(j.Index, j.Msgs, j.Leaves,
			func(e *pb.EntryUpdate) {
				mapLeaf, err := entry.ToMapLeaf(j.Index, e)
				if err != nil {
					emitErr(err)
				}
				ret = append(ret, mapLeaf)
			},
			emitErr,
		)
	}
	glog.V(2).Infof("ApplyMutations applied %v mutations to %v leaves", len(msgs), len(leaves))
	return ret, nil
}

// Joined is the result of a CoGroupByKey on []*MapLeaf and []*IndexedUpdate.
type Joined struct {
	Index  []byte
	Leaves []*pb.EntryUpdate
	Msgs   []*pb.EntryUpdate
}

// Join pairs up MapLeaves and IndexedUpdates by index.
func Join(leaves []*mapper.IndexedUpdate, msgs []*mapper.IndexedUpdate) []*Joined {
	joinMap := make(map[string]*Joined)
	for _, l := range leaves {
		row, ok := joinMap[string(l.Index)]
		if !ok {
			row = &Joined{Index: l.Index}
		}
		row.Leaves = append(row.Leaves, l.Update)
		joinMap[string(l.Index)] = row
	}
	for _, m := range msgs {
		row, ok := joinMap[string(m.Index)]
		if !ok {
			row = &Joined{Index: m.Index}
		}
		row.Msgs = append(row.Msgs, m.Update)
		joinMap[string(m.Index)] = row
	}
	ret := make([]*Joined, 0, len(joinMap))
	for _, r := range joinMap {
		ret = append(ret, r)
	}
	return ret
}

// MapUpdateFn converts an update into an IndexedUpdate.
type MapUpdateFn func(msg *pb.EntryUpdate) (*mapper.IndexedUpdate, error)

// DoMapUpdateFn runs the MapUpdateFn on each element of msgs.
func DoMapUpdateFn(fn MapUpdateFn, msgs []*pb.EntryUpdate) ([]*mapper.IndexedUpdate, error) {
	outs := make([]*mapper.IndexedUpdate, 0, len(msgs))
	for _, m := range msgs {
		out, err := fn(m)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}

// MapMapLeafFn converts an update into an IndexedUpdate.
type MapMapLeafFn func(*tpb.MapLeaf) (*mapper.IndexedUpdate, error)

func DoMapMapLeafFn(fn MapMapLeafFn, leaves []*tpb.MapLeaf) ([]*mapper.IndexedUpdate, error) {
	outs := make([]*mapper.IndexedUpdate, 0, len(leaves))
	for _, m := range leaves {
		out, err := fn(m)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}
