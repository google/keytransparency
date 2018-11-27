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

// Package mapper contains a transformation pipelines from log messages to map revisions.
package mapper

import (
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// IndexUpdate is a KV<Index, Update> type.
type IndexUpdate struct {
	Index  []byte
	Update *pb.EntryUpdate
}

// MapUpdateFn converts an update into an IndexedUpdate.
func MapUpdateFn(msg *pb.EntryUpdate) (*IndexUpdate, error) {
	var e pb.Entry
	if err := proto.Unmarshal(msg.Mutation.Entry, &e); err != nil {
		return nil, err
	}
	return &IndexUpdate{
		Index:  e.Index,
		Update: msg,
	}, nil
}

// ReduceFn decides which of multiple updates can be applied in this revision.
// TODO(gbelvin): Move to mutator interface.
func ReduceFn(mutatorFn mutator.ReduceMutationFn, index []byte, leaves []*tpb.MapLeaf, msgs []*pb.EntryUpdate, emit func(*tpb.MapLeaf)) {
	var oldValue *pb.SignedEntry // If no map leaf was found, oldValue will be nil.
	if len(leaves) > 0 {
		var err error
		oldValue, err = entry.FromLeafValue(leaves[0].GetLeafValue())
		if err != nil {
			glog.Warningf("entry.FromLeafValue(): %v", err)
			return
		}
	}

	if got := len(msgs); got < 1 {
		return
	}

	// TODO(gbelvin): Create an associative function to choose the mutation to apply.
	msg := msgs[0]
	newValue, err := mutatorFn(oldValue, msg.Mutation)
	if err != nil {
		glog.Warningf("Mutate(): %v", err)
		return // A bad mutation should not make the whole batch fail.
	}
	leafValue, err := entry.ToLeafValue(newValue)
	if err != nil {
		glog.Warningf("ToLeafValue(): %v", err)
		return
	}
	extraData, err := proto.Marshal(msg.Committed)
	if err != nil {
		glog.Warningf("proto.Marshal(): %v", err)
		return
	}
	emit(&tpb.MapLeaf{Index: index, LeafValue: leafValue, ExtraData: extraData})
}
