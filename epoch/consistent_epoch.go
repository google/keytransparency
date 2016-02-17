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

// This package represents an epoch object.
package epoch

import (
	"sync"
)

// Epoch represents a merkle tree epoch
type Epoch struct {
	// number contains the current (latest) epoch of the merkle tree.
	number int64
	// mu syncronizes access to number. mu locks when reading and advancing
	// epoch number.
	mu sync.Mutex
}

// New creates a new instalce of the epoch object.
func New() *Epoch {
	return &Epoch{}
}

// Building returns the epoch number that is been currently built.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func (e *Epoch) Building() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.number + 1
}

// Serving returns the epoch number that is been currently served.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func (e *Epoch) Serving() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.number
}

// Advance increases the epoch number by one.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func (e *Epoch) Advance() int64 {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.number = e.number + 1
	return e.number
}
