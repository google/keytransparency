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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/protobuf/jsonpb"
	"github.com/google/keytransparency/core/integration"
	"github.com/google/keytransparency/core/testdata"
	"github.com/google/trillian/storage/testdb"
)

var (
	generate    = flag.Bool("generate", false, "Defines if test vectors should be generated")
	testdataDir = flag.String("testdata", "../../core/testdata", "The directory in which to place the generated test data")
)

// TestIntegration runs all KeyTransparency integration tests.
func TestIntegration(t *testing.T) {
	// We can only run the integration tests if there is a MySQL instance available.
	testdb.SkipIfNoMySQL(t)
	for _, test := range integration.AllTests {
		t.Run(test.Name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			env, err := NewEnv(ctx)
			if err != nil {
				t.Fatalf("Could not create Env: %v", err)
			}

			defer env.Close()
			func() {
				// Cancel the test function context (and thus
				// exit any background sequencer loops)
				// *before* shutting down the server and
				// canceling the master context.
				ctx, cancel := context.WithCancel(ctx)
				defer cancel()
				resps := test.Fn(ctx, env.Env, t)
				if *generate && resps != nil {
					if err = SaveTestVectors(*testdataDir, test.DirectoryFilename, test.RespFilename, env.Env, resps); err != nil {
						t.Fatalf("saveTestVectors() failed: %v", err)
					}
				}
			}()
		})
	}
}

// SaveTestVectors generates test vectors for interoprability testing.
func SaveTestVectors(dir, directoryFilename, responseFilename string, env *integration.Env, resps []testdata.ResponseVector) error {
	marshaler := &jsonpb.Marshaler{
		Indent: "\t",
	}
	// Output all key material needed to verify the test vectors.
	directoryFile := dir + "/" + directoryFilename
	f, err := os.Create(directoryFile)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := marshaler.Marshal(f, env.Directory); err != nil {
		return fmt.Errorf("jsonpb.Marshal(): %v", err)
	}

	// Save list of responses
	respFile := dir + "/" + responseFilename
	out, err := json.MarshalIndent(resps, "", "\t")
	if err != nil {
		return fmt.Errorf("json.Marshal(): %v", err)
	}
	if err := ioutil.WriteFile(respFile, out, 0666); err != nil {
		return fmt.Errorf("writeFile(%v): %v", respFile, err)
	}
	return nil
}
