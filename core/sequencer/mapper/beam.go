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

package mapper

import (
	"github.com/apache/beam/sdks/go/pkg/beam"

	"github.com/google/keytransparency/core/directory"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// Args contains flag defined arguments to the mapper.
// Flags are only available on the master map reduce job, and must be explicitly passed
// to worker jobs.  In distributed mode, only public, JSON serializable things can be
// passed to worker jobs. Everything else must be a global.
type Args struct {
	TMap        tpb.TrillianMapClient   // Not available in distributed mode.
	MapAdmin    tpb.TrillianAdminClient // Not available in distributed mode.
	Directories directory.Storage       // Not available in distributed mode.
	DBPath      string
	MapSpec     string
}

// MakeWriteMapFn returns a WriteMapFn
func (a *Args) MakeWriteMapFn() *WriteMapFn {
	return &WriteMapFn{
		MapSpec: a.MapSpec,
		DBPath:  a.DBPath,
		factory: NewClientFactory(a.TMap, a.MapAdmin, a.Directories),
	}
}

// Pipeline returns a pipeline that can be run whith any Beam runner.
func (a *Args) Pipeline() *beam.Pipeline {
	p := beam.NewPipeline()

	dirID := ""
	leaves := []*tpb.MapLeaf{}
	meta := &spb.MapMetadata{}

	// Write to map.
	s := p.Root().Scope("WriteMapFn")
	beam.ParDo0(s, a.MakeWriteMapFn(),
		beam.Create(s, leaves),
		beam.SideInput{Input: beam.Create(s, meta)},
		beam.SideInput{Input: beam.Create(s, dirID)})

	return p
}
