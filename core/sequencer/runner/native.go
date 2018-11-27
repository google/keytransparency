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

// Package runner contains methods for running a pipeline.
package runner

import (
	"github.com/google/keytransparency/core/sequencer/mapper"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// Joined is the result of a CoGroupByKey on []*MapLeaf and []*IndexUpdate.
type Joined struct {
	Index  []byte
	Leaves []*tpb.MapLeaf
	Msgs   []*pb.EntryUpdate
}

// Join pairs up MapLeaves and IndexUpdates by index.
func Join(leaves []*tpb.MapLeaf, msgs []*mapper.IndexUpdate) []*Joined {
	joinMap := make(map[string]*Joined)
	for _, l := range leaves {
		row, ok := joinMap[string(l.Index)]
		if !ok {
			row = &Joined{}
		}
		row.Index = l.Index
		row.Leaves = append(row.Leaves, l)
		joinMap[string(l.Index)] = row
	}
	for _, m := range msgs {
		row, ok := joinMap[string(m.Index)]
		if !ok {
			row = &Joined{}
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
type MapUpdateFn func(msg *pb.EntryUpdate) (*mapper.IndexUpdate, error)

// DoMapUpdateFn runs the MapUpdateFn on each element of msgs.
func DoMapUpdateFn(fn MapUpdateFn, msgs []*pb.EntryUpdate) ([]*mapper.IndexUpdate, error) {
	outs := make([]*mapper.IndexUpdate, 0, len(msgs))
	for _, m := range msgs {
		out, err := fn(m)
		if err != nil {
			return nil, err
		}
		outs = append(outs, out)
	}
	return outs, nil
}
