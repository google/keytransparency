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

package storage

import (
	"sync"
)

const (
	// Currently commitment timestamp is implemented as a sequence number.
	// The following functionality might change when this is implemented as
	// an actual timestamp.
	StartingCommitmentTimestamp = 0
)

var (
	// current contains the current (latest) commitment timestamp of the
	// storage. Commitment timestamps are increasing but not sequential
	// uint64.
	current uint64 = StartingCommitmentTimestamp

	// mu syncronizes access to current. mu locks when reading and advancing
	// current commitment timestamp.
	mu sync.Mutex
)

// GetCurrentCommitmentTimestamp returns the current commitment timestamp.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func GetCurrentCommitmentTimestamp() uint64 {
	mu.Lock()
	defer mu.Unlock()
	return current
}

// AdvanceCommitmentTimestamp advances the commitment timestamp by one.
// TODO(cesarghali): this function should be refactored when adding support for
//                   multiple consistent key server replicas.
func AdvanceCommitmentTimestamp() uint64 {
	mu.Lock()
	defer mu.Unlock()
	current = current + 1
	return current
}
