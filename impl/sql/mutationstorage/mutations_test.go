// Copyright 2016 Google Inc. All Rights Reserved.
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
package mutationstorage

import (
	"context"
	"testing"

	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/sql/testdb"
)

func TestBatchIntegration(t *testing.T) {
	storageFactory := func(ctx context.Context, t *testing.T, _ string) (sequencer.Batcher, func(context.Context)) {
		db, done := testdb.NewForTest(ctx, t)
		m, err := New(db)
		if err != nil {
			t.Fatalf("Failed to create mutations: %v", err)
		}
		return m, done
	}

	storagetest.RunBatchStorageTests(t, storageFactory)
}
