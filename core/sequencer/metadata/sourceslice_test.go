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
	"testing"
	"time"

	"github.com/golang/protobuf/proto"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

func TestValidateTime(t *testing.T) {
	for _, tc := range []struct {
		ts    time.Time
		valid bool
	}{
		{ts: time.Time{}, valid: false},
		{ts: time.Date(1, 0, 0, 0, 0, 0, 0, time.UTC), valid: false},
		{ts: time.Date(1000, 0, 0, 0, 0, 0, 0, time.UTC), valid: false},
		{ts: time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC), valid: true},
		{ts: time.Date(200000, 0, 0, 0, 0, 0, 0, time.UTC), valid: false},
	} {
		err := validateTime(tc.ts)
		if got := err == nil; got != tc.valid {
			t.Errorf("validateTime(%v): %v, want valid: %v", tc.ts, err, tc.valid)
		}
	}
}

func TestTimeToProto(t *testing.T) {
	logID := int64(1)
	for _, tc := range []struct {
		low, high time.Time
		want      *spb.MapMetadata_SourceSlice
	}{
		{low: time.Unix(0, 0), high: time.Unix(0, 0), want: &spb.MapMetadata_SourceSlice{LogId: logID, LowestInclusive: 0}},
		{low: time.Unix(0, 1), high: time.Unix(0, 0), want: &spb.MapMetadata_SourceSlice{LogId: logID, LowestInclusive: 1}},
		{low: time.Unix(0, 1000), high: time.Unix(0, 0), want: &spb.MapMetadata_SourceSlice{LogId: logID, LowestInclusive: 1}},
		{low: time.Unix(1, 0), high: time.Unix(0, 0), want: &spb.MapMetadata_SourceSlice{LogId: logID, LowestInclusive: 1000000}},
		{low: time.Unix(1, 0), high: time.Unix(1, 0), want: &spb.MapMetadata_SourceSlice{LogId: logID, LowestInclusive: 1000000, HighestExclusive: 1000000}},
	} {
		ss, err := New(logID, tc.low, tc.high)
		if err != nil {
			t.Fatal(err)
		}
		if got := ss.Proto(); !proto.Equal(got, tc.want) {
			t.Errorf("New().Proto(): %v, want %v", got, tc.want)
		}
	}
}
