// Copyright 2020 Google Inc. All Rights Reserved.
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

package election

import (
	"context"
	"testing"
	"time"

	"github.com/google/keytransparency/internal/forcemaster"
	"github.com/google/trillian/monitoring"
)

// Ensure that mastership continues to work after resignTime.
func TestForceMaster(t *testing.T) {
	ctx, done := context.WithCancel(context.Background())
	defer done()
	resignTime := 1 * time.Hour
	res := "test resource"

	mt := NewTracker(forcemaster.Factory{}, resignTime, monitoring.InertMetricFactory{})
	go mt.Run(ctx)
	mt.AddResource(res)
	time.Sleep(time.Millisecond) // Wait to acquire mastership.

	// Verify that mastersihp works as expected, with 1 mastership for res.
	m, err := mt.Masterships(ctx)
	if err != nil {
		t.Error(err)
	}
	if got := len(m); got != 1 {
		t.Errorf("Masterships returned %v, want 1", got)
	}

	// Advance the clock by pretending we acquired mastersihp a long time ago.
	mt.masterMu.Lock()
	mastership := mt.master[res]
	mastership.acquired = time.Now().Add(-2 * resignTime)
	mt.master[res] = mastership
	mt.masterMu.Unlock()

	// Verify that we resign the mastership after the clock as advanced.
	m2, err := mt.Masterships(ctx)
	if err != nil {
		t.Error(err)
	}
	if got := len(m2); got != 0 {
		t.Errorf("Masterships returned %v, want 0", got)
	}

	time.Sleep(time.Millisecond) // Wait to acquire mastership.

	// Verify that we reaquire mastership
	m3, err := mt.Masterships(ctx)
	if err != nil {
		t.Error(err)
	}
	if got := len(m3); got != 1 {
		t.Errorf("Masterships returned %v, want 0", got)
	}
}
