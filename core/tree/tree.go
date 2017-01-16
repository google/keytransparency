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

// Package tree contains functions for manipulating generic tree representations.
package tree

import (
	"context"

	"github.com/google/key-transparency/core/transaction"
)

// Sparse is a temporal sparse merkle tree.
type Sparse interface {
	// QueueLeaf queues a leaf to be written on the next Commit().
	QueueLeaf(txn transaction.Txn, index, leaf []byte) error
	// Commit takes all the Queued values since the last Commmit() and writes them.
	// Commit is NOT multi-process safe. It should only be called from the sequencer.
	Commit(ctx context.Context) (epoch int64, err error)
	// ReadRootAt returns the root value at epoch.
	ReadRootAt(txn transaction.Txn, epoch int64) ([]byte, error)
	// ReadLeafAt returns the leaf value at epoch.
	ReadLeafAt(txn transaction.Txn, index []byte, epoch int64) ([]byte, error)
	// Neighbors returns the list of neighbors from the neighbor leaf to just below the root at epoch.
	NeighborsAt(ctx context.Context, index []byte, epoch int64) ([][]byte, error)
	// Epoch returns the current epoch of the merkle tree.
	Epoch() int64
}
