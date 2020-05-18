// Copyright 2016 Google Inc. All Rights Reserved.
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

// Package entry implements a simple replacement strategy as a mapper.
package entry

import (
	"errors"
	"fmt"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

// IndexedValue is a KV<Index, Value> type.
type IndexedValue struct {
	Index []byte
	Value *pb.EntryUpdate
}

// Unmarshal parses the contents of leaf and places them in the receiver.
func (iv *IndexedValue) Unmarshal(leaf *tpb.MapLeaf) error {
	if iv == nil {
		return errors.New("entry: nil receiver")
	}

	mutation, err := FromLeafValue(leaf.GetLeafValue())
	if err != nil {
		return err
	}

	// Don't set committed if there was no data for it.
	var committed *pb.Committed // nil
	if leaf.GetExtraData() != nil {
		val := &pb.Committed{}
		if err := proto.Unmarshal(leaf.ExtraData, val); err != nil {
			return err
		}
		committed = val
	}
	if mutation == nil && committed == nil {
		*iv = IndexedValue{Index: leaf.GetIndex()}
		return nil
	}
	*iv = IndexedValue{
		Index: leaf.GetIndex(),
		Value: &pb.EntryUpdate{
			Mutation:  mutation,
			Committed: committed,
		},
	}
	return nil
}

// Marshal converts IndexedValue to a Trillian Map Leaf.
func (iv *IndexedValue) Marshal() (*tpb.MapLeaf, error) {
	if iv == nil {
		return nil, errors.New("entry: nil receiver")
	}
	// Convert to MapLeaf
	leafValue, err := ToLeafValue(iv.Value.GetMutation())
	if err != nil {
		return nil, fmt.Errorf("entry: ToLeafValue(): %v", err)
	}
	extraData, err := proto.Marshal(iv.Value.GetCommitted())
	if err != nil {
		return nil, fmt.Errorf("entry: proto.Marshal(): %v", err)
	}
	return &tpb.MapLeaf{Index: iv.Index, LeafValue: leafValue, ExtraData: extraData}, nil
}

// FromLeafValue takes a trillian.MapLeaf.LeafValue and returns and instantiated
// Entry or nil if the passes LeafValue was nil.
func FromLeafValue(value []byte) (*pb.SignedEntry, error) {
	if value != nil {
		entry := new(pb.SignedEntry)
		if err := proto.Unmarshal(value, entry); err != nil {
			glog.Warningf("proto.Unmarshal(%v, _): %v", value, err)
			return nil, err
		}
		return entry, nil
	}
	// For the very first mutation we will have
	// resp.LeafProof.MapLeaf.LeafValue=nil.
	return nil, nil
}

// ToLeafValue converts the update object into a serialized object to store in the map.
func ToLeafValue(update *pb.SignedEntry) ([]byte, error) {
	return proto.Marshal(update)
}
