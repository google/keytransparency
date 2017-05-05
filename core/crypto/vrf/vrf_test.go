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

package vrf

import (
	"bytes"
	"testing"
)

func TestUniqueID(t *testing.T) {
	for _, tc := range []struct {
		userID, appID   string
		muserID, mappID string
	}{
		{"foo", "app", "fooa", "pp"},
		{"foo", "app", "", "fooapp"},
	} {
		if got, want :=
			UniqueID(tc.userID, tc.appID),
			UniqueID(tc.muserID, tc.mappID); bytes.Equal(got, want) {
			t.Errorf("UniqueID(%v, %v) == UniqueID(%v, %v): %s, want !=", tc.userID, tc.appID, tc.muserID, tc.mappID, got)
		}
	}
}
