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

// Package water provides the watermark type.
package water

// Mark is wrapper for uint64 representing a watermark, or a logical timestamp.
// Some implementations use an actual timestamp in micro- or nanoseconds, some
// use more generic sequence numbers.
type Mark struct {
	value uint64
}

// NewMark returns a watermark from the given integer value.
func NewMark(value uint64) Mark {
	return Mark{value: value}
}

// Value returns the uint64 representation of the watermark.
func (m Mark) Value() uint64 {
	return m.value
}

// Add increments the watermark by the passed in value.
func (m Mark) Add(value uint64) Mark {
	return Mark{value: m.value + value}
}

// Compare returns the result of comparing this Mark with with the other.
func (m Mark) Compare(other Mark) int {
	if m.value < other.value {
		return -1
	} else if m.value > other.value {
		return 1
	}
	return 0
}
