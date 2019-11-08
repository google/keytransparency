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
package metadata

import (
	"testing"
	"time"
)

func TestValidateTime(t *testing.T) {
	for _, tc := range []struct {
		ts    time.Time
		valid bool
	}{
		{ts: time.Time{}, valid: false},
		{ts: time.Date(1, 0, 0, 0, 0, 0, 0, time.UTC), valid: false},
		{ts: time.Date(1000, 0, 0, 0, 0, 0, 0, time.UTC), valid: false},
		{ts: time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC), valid: true},
	} {
		err := validateTime(tc.ts)
		if got := err == nil; got != tc.valid {
			t.Errorf("validateTimestamp(%v): %v, want valid: %v", tc.ts, err, tc.valid)
		}
	}
}
