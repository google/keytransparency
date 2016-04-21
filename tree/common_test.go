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
	"bytes"
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
	for _, tc := range locationTests {
		if got, want := BitString(tc.location), tc.bstring; got != want {
			t.Errorf("BitString(%v) = %v, want %v", tc.location, got, want)
		}
	}
}

func TestNeighborIndex(t *testing.T) {
	tests := []struct {
		index    []byte
		depth    int
		neighbor []byte
	}{
		{[]byte{0x00}, 0, []byte{0x80}},
		{[]byte{0x00}, 1, []byte{0x40}},
		{[]byte{0x00}, 7, []byte{0x01}},
		{[]byte{0x00}, 6, []byte{0x02}},
		{[]byte{0x08}, 4, []byte{0x00}},
		{[]byte{0x08}, 0, []byte{0x88}},
		{[]byte{0x00, 0x00}, 0, []byte{0x80, 0x00}},
		{[]byte{0x00, 0x00, 0x00}, 0, []byte{0x80, 0x00, 0x00}},
	}
	for _, tc := range tests {
		if got := NeighborIndex(tc.index, tc.depth); !bytes.Equal(got, tc.neighbor) {
			t.Errorf("NeighborIndex(%v, %v) = %v, want %v", tc.index, tc.depth, got, tc.neighbor)
		}
	}
}
