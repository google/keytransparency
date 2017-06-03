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

package dev

import (
	"strings"
	"testing"
)

func TestZeros(t *testing.T) {
	for i, tc := range []struct {
		in []byte
	}{
		{nil},
		{[]byte{}},
		{[]byte{1}},
		{[]byte(strings.Repeat("A", 300))},
	} {
		n, err := Zeros.Read(tc.in)
		if err != nil {
			t.Errorf("%v: Zeros.Read(%v): _, %v, want nil", i, tc.in, err)
		}
		if got, want := n, len(tc.in); got != want {
			t.Errorf("%v: Zeros.Read(%v): %v, want %v", i, tc.in, got, want)
		}
		for j, c := range tc.in {
			if got, want := c, byte(0); got != want {
				t.Errorf("%v: Zeros.Read(%v)[%v]: %v, want %v", i, tc.in, j, got, want)
			}
		}
	}
}
