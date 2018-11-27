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
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
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
