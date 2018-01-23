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
	"testing"

	"github.com/google/keytransparency/core/integration"
	"github.com/google/trillian/storage/testdb"
)

// TestIntegration runs all KeyTransparency integration tests.
func TestIntegration(t *testing.T) {
	// We can only run the integration tests if there is a MySQL instance available.
	if provider := testdb.Default(); !provider.IsMySQL() {
		t.Skipf("Skipping KT integration test, SQL driver is %v", provider.Driver)
	}

	ctx := context.Background()

	for _, test := range integration.AllTests {
		t.Run(test.Name, func(t *testing.T) {
			env, err := NewEnv()
			if err != nil {
				t.Fatalf("Could not create Env: %v", err)
			}
			defer env.Close()
			test.Fn(ctx, env.Env, t)
		})
	}
}
