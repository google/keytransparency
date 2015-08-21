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
	"sync"
)

var (
	// current contains the current (latest) epoch of the merkle tree.
	current uint64 = 0

	// mu syncronizes access to current. mu locks when reading and advancing
	// current epoch.
	mu sync.Mutex
)

// GetCurrentEpoch returns the current epoch number.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func GetCurrentEpoch() uint64 {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// AdvanceEpoch advances the epoch by one.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func AdvanceEpoch() uint64 {
	mu.Lock()
	defer mu.Unlock()
	current = current + 1
	return current
}
