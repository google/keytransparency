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
	"context"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// NativeRunner runs the pipeline locally using go channels.
type NativeRunner struct {
	Args *Args
}

// RunMapper runs the mapping function locally using go channels.
func (r *NativeRunner) RunMapper(ctx context.Context) error {

	dirID := ""
	leaves := []*tpb.MapLeaf{}
	meta := &spb.MapMetadata{}

	// Setup Pipeline
	writeMapFn := r.Args.MakeWriteMapFn()
	if err := writeMapFn.Setup(ctx); err != nil {
		return err
	}
	defer writeMapFn.Teardown()
	if err := writeMapFn.ProcessElement(ctx, leaves, meta, dirID); err != nil {
		return err
	}
	return nil
}
