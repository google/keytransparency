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

import (
	"github.com/google/keytransparency/core/transaction"
	"golang.org/x/net/context"
)

// Queuer submits new mutations to be processed.
type Queuer interface {
	// Enqueue submits a key, value pair for processing.
	// Duplicate key, value pairs will be processed in the order received by
	// the queue. Mutations SHOULD explicitly reference any data they modify
	// to be robust across epoch updates.
	Enqueue(key, value []byte) error

	// Commit all enqueued items to the sparse merkle tree.
	AdvanceEpoch() error

	// StartReceiving starts receiving queue enqueued items.
	StartReceiving(processFunc ProcessKeyValueFunc, advanceFunc AdvanceEpochFunc) (Receiver, error)
}

// Receiver represents a queue receiver.
type Receiver interface {
	// Close stops the receiver from receiving items from the queue.
	Close()
}

// ProcessKeyValueFunc is a function that processes a mutation.
type ProcessKeyValueFunc func(ctx context.Context, txn transaction.Txn, sequence uint64, key, value []byte) error

// AdvanceEpochFunc is a function that advances the epoch.
type AdvanceEpochFunc func(ctx context.Context, txn transaction.Txn) error
