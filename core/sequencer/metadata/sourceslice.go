// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package metadata helps enforce a consistent standard of meaning around the map metadata object.
package metadata

import (
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	"github.com/google/keytransparency/core/water"
)

// New creates a new source slice from watermarks for the given log.
func New(logID int64, low, high water.Mark) *SourceSlice {
	// TODO(pavelkalinnikov): Consider checking low <= high.
	// TODO(pavelkalinnikov): uint64->int64 check.
	return &SourceSlice{s: &spb.MapMetadata_SourceSlice{
		LogId:            logID,
		LowestInclusive:  int64(low.Value()),
		HighestExclusive: int64(high.Value()),
	}}
}

// FromProto returns a wrapper for the given proto SourceSlice.
func FromProto(s *spb.MapMetadata_SourceSlice) *SourceSlice {
	return &SourceSlice{s: s}
}

// SourceSlice is a helper for the MapMetadata_SourceSlice proto message.
type SourceSlice struct {
	s *spb.MapMetadata_SourceSlice
}

// LowMark returns LowestInclusive as a watermark.
func (s SourceSlice) LowMark() water.Mark {
	return water.NewMark(uint64(s.s.GetLowestInclusive()))
}

// HighMark returns HighestExclusive as a watermark.
func (s SourceSlice) HighMark() water.Mark {
	return water.NewMark(uint64(s.s.GetHighestExclusive()))
}

// Proto returns the proto representation of the SourceSlice.
func (s *SourceSlice) Proto() *spb.MapMetadata_SourceSlice {
	return s.s
}
