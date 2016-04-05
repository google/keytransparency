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

package tree

import (
	"strings"
	"testing"
)

func TestNeighbors(t *testing.T) {
	bindex := "0100"
	expected := []string{"0101", "011", "00", "1"}
	actual := Neighbors(bindex)
	if got, want := len(actual), len(expected); got != want {
		t.Errorf("len(%v)=%v, want %v", actual, got, want)
	}
	for i := 0; i < len(actual); i++ {
		if got, want := actual[i], expected[i]; got != want {
			t.Errorf("%v: %v, want %v", i, got, want)
		}
	}
}

func TestPath(t *testing.T) {
	bindex := "0100"
	expected := []string{"0100", "010", "01", "0", ""}
	actual := Path(bindex)
	if got, want := len(actual), len(expected); got != want {
		t.Errorf("len(%v)=%v, want %v", actual, got, want)
	}
	for i := 0; i < len(actual); i++ {
		if got, want := actual[i], expected[i]; got != want {
			t.Errorf("%v: %v, want %v", i, got, want)
		}
	}
}

func TestBitString(t *testing.T) {
	var locationTests = []struct {
		location []byte
		bstring  string
	}{
		{[]byte("\x00"), strings.Repeat("0", 256)},
		{[]byte("\x01"), strings.Repeat("0", 255) + "1"},
		{[]byte("\x80"), strings.Repeat("0", 248) + "10000000"},
	}
	for _, tt := range locationTests {
		if got, want := BitString(tt.location), tt.bstring; got != want {
			t.Errorf("BitString(%v) = %v, want %v", tt.location, got, want)
		}
	}
}
