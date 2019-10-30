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

package integration

import (
	"context"
	"flag"
	"testing"

	"github.com/google/keytransparency/core/integration"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/trillian/storage/testdb"

	tpb "github.com/google/keytransparency/core/testdata/transcript_go_proto"
)

var generate = flag.Bool("generate", false, "Defines if test vectors should be generated")

// TestIntegration runs all KeyTransparency integration tests.
func TestIntegration(t *testing.T) {
	// We can only run the integration tests if there is a MySQL instance available.
	testdb.SkipIfNoMySQL(t)
	for _, test := range integration.AllTests {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env := NewEnv(ctx, t)
			defer env.Close()
			cctx, cancel := context.WithCancel(ctx)
			actions := test.Fn(cctx, env.Env, t)
			// Cancel the test function context (and thus exit any
			// background sequencer loops) *before* shutting down
			// the server and canceling the master context.
			cancel()
			if *generate {
				if err := testdata.WriteTranscript(test.Name, &tpb.Transcript{
					Description: test.Name,
					Directory:   env.Env.Directory,
					Actions:     actions,
				}); err != nil {
					t.Fatalf("WriteTranscript() failed: %v", err)
				}
			}
		})
	}
}
