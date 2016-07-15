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

// Package queue implements a single-reader, multi-writer distributed queue.
package queue

// Queuer submits new mutations to be processed.
type Queuer interface {
	// Enqueue submits a key, value pair for processing.
	// Duplicate key, value pairs will be procesed in the order recieved by
	// the queue. Mutations SHOULD explicitly reference any data they modify
	// to be robust across epoch updates.
	Enqueue(key, value []byte) error

	// Commit all enqueued items to the sparse merkle tree.
	AdvanceEpoch() error

	// Dequeue consumes one item from the queue.  Item is only dequeued if
	// the function called, processFunc or advanceFunc, succeeds.
	// There is no locking around an item that is currently being processed.
	// If Dequeue is called concurrently, multiple processes will dequeue
	// the same data. Correlary: if a crash occurs during processing, the
	// next process will dequeue the same item to continue.
	Dequeue(processFunc ProcessKeyValueFunc, advanceFunc AdvanceEpochFunc) error
}

// ProcessKeyValueFunc is a function that processes a mutation.
type ProcessKeyValueFunc func(key, value []byte) error

// AdvanceEpochFunc is a function that advances the epoch.
type AdvanceEpochFunc func() error
