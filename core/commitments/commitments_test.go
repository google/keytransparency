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

// Package commitments contains common type definitions and functions used by other
// packages. Types that can cause circular import should be added here.
package commitments

import (
	"testing"
)

func TestCommit(t *testing.T) {
	for _, tc := range []struct {
		userID, data string
	}{
		{"foo", "bar"},
	} {
		k, c, err := Commit(tc.userID, []byte(tc.data))
		if err != nil {
			t.Errorf("Commit(%v, %x): %v", tc.userID, tc.data, err)
		}
		if err := Verify(tc.userID, k, c); err != nil {
			t.Errorf("Verify(%v, %x, %v): %v", tc.userID, k, c, err)
		}
	}
}
