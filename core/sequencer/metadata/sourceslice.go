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
	"fmt"
	"math"
	"time"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

var minTime = time.Unix(0, math.MinInt64) // 1677-09-21 00:12:43.145224192
var maxTime = time.Unix(0, math.MaxInt64) // 2262-04-11 23:47:16.854775807

// validateTime determines whether a timestamp is valid.
// Valid timestamps can be represented by an int64 number of microseconds from the epoch.
//
// Every valid timestamp can be represented by a time.Time, but the converse is not true.
func validateTime(ts time.Time) error {
	if ts.Before(minTime) {
		return fmt.Errorf("timestamp %v before %v", ts, minTime)
	}
	if ts.After(maxTime) {
		return fmt.Errorf("timestamp %v after %v", ts, maxTime)
	}
	return nil
}

// New creates a new source slice from time objects.
// Returns an error if the time objects cannot be represented correctly.
func New(logID int64, low, high time.Time) (*SourceSlice, error) {
	if err := validateTime(low); err != nil {
		return nil, err
	}
	if err := validateTime(high); err != nil {
		return nil, err
	}
	return &SourceSlice{s: &spb.MapMetadata_SourceSlice{
		LogId:            logID,
		LowestInclusive:  low.UnixNano(),
		HighestExclusive: high.UnixNano(),
	}}, nil
}

// FromProto returns a wrapper for SourceSlice
func FromProto(s *spb.MapMetadata_SourceSlice) *SourceSlice {
	return &SourceSlice{s: s}
}

// SourceSlice defines accessor and conversion methods for MapMetadata_SourceSlice
// TODO(gbelvin): fully migrate to source slices that encode time directly.
// For now, we need to have a wrapper to do the conversions between time and int64 consistently.
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

// Proto returns the proto representation of SourceSlice
func (s *SourceSlice) Proto() *spb.MapMetadata_SourceSlice {
	return s.s
}
