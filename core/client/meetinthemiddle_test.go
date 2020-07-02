// Copyright 2020 Google LLC. All Rights Reserved.
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

package client

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAllPairsOverlap(t *testing.T) {
	max := uint64(100)
	for created := uint64(1); created < max; created++ {
		for current := created; current < max; current++ {
			for diff := uint64(0); diff < 1; diff++ {
				newer := NewerRevisionsToVerify(created, current, 0)
				older := OlderRevisionsToVerify(current+diff, 0)
				t.Logf("newer: (%v, %v):\t%v", created, current, newer)
				t.Logf("older: (%v):\t%v", current+diff, older)

				set := make(map[uint64]bool)
				overlap := []uint64{}
				for _, rev := range newer {
					set[rev] = true
				}
				for _, rev := range older {
					if _, ok := set[rev]; ok {
						overlap = append(overlap, rev)
					}
				}
				if got := len(overlap); got != 1 {
					t.Fatalf("overlap: %v, want 1", got)
				}
			}
		}
	}
}

func TestMeetInTheMiddleOverlap(t *testing.T) {
	for i, tc := range []struct {
		created uint64
		current uint64
		diff    uint64
		fail    bool
	}{
		// Failure for created > current
		{created: 0, current: 0, fail: true},
		{created: 2, current: 1, fail: true},
		// All combinations of current > 1, diff = 0 overlap.
		{created: 0, current: 1},
		{created: 1, current: 1},
		{created: 1, current: 128},
		{created: 127, current: 127},
		{created: 128, current: 128},
		{created: 129, current: 1000000},
		// Failure when diff >= current
		{created: 1, current: 128, diff: 127},
		{created: 1, current: 128, diff: 128, fail: true},
		{created: 128, current: 256, diff: 255},
		{created: 128, current: 256, diff: 256, fail: true},
		{created: 256, current: 256, diff: 256, fail: true},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			newer := NewerRevisionsToVerify(tc.created, tc.current, 0)
			older := OlderRevisionsToVerify(tc.current+tc.diff, 0)
			t.Logf("newer: %v", newer)
			t.Logf("older: %v", older)

			set := make(map[uint64]bool)
			overlap := []uint64{}
			for _, rev := range newer {
				set[rev] = true
			}
			for _, rev := range older {
				if _, ok := set[rev]; ok {
					overlap = append(overlap, rev)
				}
			}
			if fail := len(overlap) != 1; fail != tc.fail {
				t.Errorf("overlap: %v, want no overlap: %v", overlap, tc.fail)
			}
		})
	}
}

func TestVerified(t *testing.T) {
	// Ensure that, as the revisions verified grow, we accumulate all revisions.
	max := uint64(100)
	for created := uint64(1); created < max; created++ {
		for current := created; current < max; current++ {
			want := map[uint64]bool{}
			for _, r := range NewerRevisionsToVerify(created, current, 0) {
				want[r] = true
			}
			got := map[uint64]bool{}
			for verified := uint64(0); verified < current; verified++ {
				for _, r := range NewerRevisionsToVerify(created, current, verified) {
					got[r] = true
				}
			}
			if !cmp.Equal(got, want) {
				t.Fatalf("accumulated NewerRevisionsToVerify(%v, %v, all): %v, want %v",
					created, current, got, want)
			}
		}
	}
}
