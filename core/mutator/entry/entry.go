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
	"fmt"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

func FromMapLeaf(leaf *tpb.MapLeaf) (*pb.EntryUpdate, error) {
	mutation, err := FromLeafValue(leaf.GetLeafValue())
	if err != nil {
		return nil, err
	}
	var committed pb.Committed
	if err := proto.Unmarshal(leaf.GetExtraData(), &committed); err != nil {
		return nil, err
	}
	return &pb.EntryUpdate{
		Mutation:  mutation,
		Committed: &committed,
	}, nil
}

func ToMapLeaf(index []byte, e *pb.EntryUpdate) (*tpb.MapLeaf, error) {
	// Convert to MapLeaf
	leafValue, err := ToLeafValue(e.Mutation)
	if err != nil {
		return nil, fmt.Errorf("entry: ToLeafValue(): %v", err)
	}
	extraData, err := proto.Marshal(e.Committed)
	if err != nil {
		return nil, fmt.Errorf("entry: proto.Marshal(): %v", err)
	}
	return &tpb.MapLeaf{Index: index, LeafValue: leafValue, ExtraData: extraData}, nil
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
