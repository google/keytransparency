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

package memory

import (
	"context"
	"testing"

	"github.com/google/keytransparency/core/integration/storagetest"
	"github.com/google/keytransparency/core/keyserver"
)

// Tests for the tests!
func TestMutationLogsIntegration(t *testing.T) {
	storagetest.RunMutationLogsTests(t,
		func(ctx context.Context, t *testing.T, dirID string, logIDs ...int64) (keyserver.MutationLogs, func(context.Context)) {
			m := NewMutationLog()
			m.AddLogs(ctx, dirID, logIDs...)
			return m, func(context.Context) {}
		})
}
