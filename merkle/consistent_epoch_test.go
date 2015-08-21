// Copyright 2015 Google Inc. All Rights Reserved.
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

package merkle

import (
	"testing"
)

func TestAdvance(t *testing.T) {
	tests := []struct {
		numOfIncrements int
		outEpoch        uint64
		success         bool
	}{
		// Advancing epoch is cumulative.
		{1, 1, true},
		{3, 4, true},
		{1, 0, false},
	}

	for i, test := range tests {
		for j := 0; j < test.numOfIncrements; j++ {
			AdvanceEpoch()
		}
		if got, want := GetCurrentEpoch() == test.outEpoch, test.success; got != want {
			t.Errorf("Test[%v]: GetCurrentEpoch()=%v, want %v, should fail: %v", i, GetCurrentEpoch(), test.outEpoch, !test.success)
		}
	}
}
