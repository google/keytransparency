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

// Package mapper contains a transformation pipeline from log messages to map revisions.
package mapper

import (
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/keytransparency/core/mutator/entry"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// MapMetaFn emits the source slices referenced by meta.
func MapMetaFn(meta *spb.MapMetadata, emit func(*spb.MapMetadata_SourceSlice)) {
	for _, source := range meta.Sources {
		emit(source)
	}
}

// MapMapLeaf converts a map leaf into an entry.IndexedValue.
func MapMapLeafFn(leaf *tpb.MapLeaf) (*entry.IndexedValue, error) {
	iv := &entry.IndexedValue{}
	if err := iv.Unmarshal(leaf); err != nil {
		return nil, err
	}
	return iv, nil
}

// MapUpdateFn converts an update into an entry.IndexedValue.
func MapUpdateFn(msg *pb.EntryUpdate) (*entry.IndexedValue, error) {
	var e pb.Entry
	if err := proto.Unmarshal(msg.GetMutation().GetEntry(), &e); err != nil {
		return nil, err
	}
	return &entry.IndexedValue{
		Index: e.Index,
		Value: msg,
	}, nil
}
