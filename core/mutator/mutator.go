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

// Package mutator defines the operations to transform mutations into changes in
// the map as well as operations to write and read mutations to and from the
// database.
package mutator

import (
	"context"
	"errors"

	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

var (
	// MaxMutationSize represent the maximum allowed mutation size in bytes.
	MaxMutationSize = 16 * 1024
	// ErrReplay occurs when two mutations acting on the same entry & epoch
	// occur.
	ErrReplay = errors.New("mutation replay")
	// ErrSize occurs when the mutation size is larger than the allowed upper
	// bound.
	ErrSize = errors.New("mutation: too large")
	// ErrPreviousHash occurs when the mutation the hash of the previous
	// entry provided in the mutation does not match the previous entry
	// itself.
	ErrPreviousHash = errors.New("mutation: previous entry hash does not match the hash provided in the mutation")
	// ErrInvalidSig occurs when either the current or previous update entry
	// signature verification fails.
	ErrInvalidSig = errors.New("mutation: invalid signature")
	// ErrUnauthorized occurs when the mutation has not been signed by a key in the
	// previous entry.
	ErrUnauthorized = errors.New("mutation: unauthorized")
)

// Func verifies mutations and transforms values in the map.
type Func interface {
	// Mutate verifies that this is a valid mutation for this item and
	// applies mutation to value.
	Mutate(value, mutation proto.Message) (proto.Message, error)
}

// QueueMessage represents a change to a user, and associated data.
type QueueMessage struct {
	ID        int64
	Mutation  *pb.Entry
	ExtraData *pb.Committed
}

// MutationQueue provides (at minimum) a roughly time ordered queue that can support
// multiple writers.  Replays, drops, and duplicate delivery must be tolerated by
// receivers.
type MutationQueue interface {
	// Send submits an item to the queue
	Send(ctx context.Context, domainID string, mutation *pb.EntryUpdate) error
}

// ReceiveFunc receives updates from the queue.
type ReceiveFunc func([]*QueueMessage) error

// Receiver receives messages from a queue.
type Receiver interface {
	// Close stops the receiver and returns only when all callbacks are complete.
	Close()
	// FlushN waits for n items and then sends them.
	// Deterministic implementations that can't wait will return an error.
	FlushN(context.Context, int) error
}

// MutationStorage reads and writes mutations to the database.
type MutationStorage interface {
	// ReadPage returns mutations in the interval (start, end] for mapID.
	// pageSize specifies the maximum number of items to return.
	// Returns the maximum sequence number returned.
	ReadPage(ctx context.Context, domainID string, revision, start int64, pageSize int32) (int64, []*pb.Entry, error)
	// WriteBatch saves the mutations in the database under domainID/revision.
	WriteBatch(ctx context.Context, domainID string, revision int64, mutation []*pb.Entry) error
}
