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

package metadata

import (
	"time"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

// Source returns a wrapper for SourceSlice
func Source(s *spb.MapMetadata_SourceSlice) SourceSlice {
	return SourceSlice{s: s}
}

// SourceSlice defines accessor and conversion methods for MapMetadata_SourceSlice
type SourceSlice struct {
	s *spb.MapMetadata_SourceSlice
}

// StartTime returns LowestInclusive as a time.Time
func (s SourceSlice) StartTime() time.Time {
	return time.Unix(0, s.s.GetLowestInclusive())
}

// EndTime returns HighestExclusive as a time.Time
func (s SourceSlice) EndTime() time.Time {
	return time.Unix(0, s.s.GetHighestExclusive())
}
