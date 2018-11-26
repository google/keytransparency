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

	"github.com/apache/beam/sdks/go/pkg/beam/runners/direct"
)

// DirectRunner runs the pipeline locally using beam.
type DirectRunner struct {
	Args *Args
}

// RunMapper executes the mapping function locally using Beam.
func (r *DirectRunner) RunMapper(ctx context.Context) error {
	return direct.Execute(ctx, r.Args.Pipeline())
}
