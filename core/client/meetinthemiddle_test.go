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

package client

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestMeetInTheMiddleOverlap(t *testing.T) {
	for i, tc := range []struct {
		created,
		current int64
		diff int64
		fail bool
	}{
		// Non converging zero situations.
		{created: 0, current: 0, fail: true},
		{created: 129, current: 0, fail: true},
		// All combinations of current > 1, diff = 0 overlap.
		{created: 1, current: 1},
		{created: 1, current: 128},
		{created: 127, current: 127},
		{created: 128, current: 128},
		{created: 129, current: 1000000},
		{created: rand.Int63(), current: rand.Int63()},
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

			set := make(map[int64]bool)
			overlap := []int64{}
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
