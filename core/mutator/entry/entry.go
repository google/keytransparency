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
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

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
