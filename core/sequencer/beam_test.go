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

package sequencer

import (
	"context"
	"fmt"
	"testing"

	"github.com/apache/beam/sdks/go/pkg/beam"
	"github.com/apache/beam/sdks/go/pkg/beam/transforms/stats"
	"github.com/apache/beam/sdks/go/pkg/beam/x/beamx"
	"github.com/google/keytransparency/core/mutator"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

func TestReadMessages(t *testing.T) {
	ctx := context.Background()
	directoryID := "directoryID"
	s := Server{logs: fakeLogs{
		0: make([]mutator.LogMessage, 10),
		1: make([]mutator.LogMessage, 20),
	}}

	for _, tc := range []struct {
		meta      *spb.MapMetadata
		batchSize int32
		want      int
	}{
		{batchSize: 1, want: 9, meta: &spb.MapMetadata{Sources: SourcesEntry{
			0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9},
		}}},
		{batchSize: 1, want: 19, meta: &spb.MapMetadata{Sources: SourcesEntry{
			0: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 9},
			1: &spb.MapMetadata_SourceSlice{LowestWatermark: 0, HighestWatermark: 10},
		}}},
	} {
		p := beam.NewPipeline()
		scope := p.Root()

		meta := beam.Create(scope, tc.meta)
		// Read each logID in parallel.
		sourceSlices := beam.ParDo(scope, splitMeta, meta) // KV<logID, source>
		logItems := beam.ParDo(scope, s.readOneLog, sourceSlices,
			beam.SideInput{Input: beam.Create(scope, directoryID)},
			beam.SideInput{Input: beam.Create(scope, tc.batchSize)})
		count := stats.Sum(scope, beam.DropKey(scope, stats.Count(scope, logItems)))
		beam.ParDo0(scope, func(got int) error {
			if got != tc.want {
				return fmt.Errorf("readMessages(): len: %v, want %v", got, tc.want)
			}
			return nil
		}, count)

		if err := beamx.Run(ctx, p); err != nil {
			t.Errorf("beamx.Run(): %v", err)
		}

	}
}
