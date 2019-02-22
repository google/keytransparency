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
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

var (
	// MaxMutationSize represent the maximum allowed mutation size in bytes.
	MaxMutationSize = 16 * 1024
	// ErrReplay occurs when two mutations acting on the same entry & revision
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
	ErrUnauthorized = status.Errorf(codes.PermissionDenied, "mutation: unauthorized")
)

// VerifyMutationFn verifies that a mutation is internally consistent.
type VerifyMutationFn func(mutation *pb.SignedEntry) error

// ReduceMutationFn takes the existing mapleaf and a new mutation and returns the new value for that map leaf.
// ReduceMutationFn verifies that this is a valid mutation for this item.
// ReduceMutationFn must be idempotent.
type ReduceMutationFn func(existingMapLeafValue, mutation *pb.SignedEntry) (*pb.SignedEntry, error)

// MapLogItemFn takes a log item and emits 0 or more KV<index, mutations> pairs.
type MapLogItemFn func(logItem *LogMessage, emit func(index []byte, mutation *pb.EntryUpdate)) error

// LogMessage represents a change to a user, and associated data.
type LogMessage struct {
	ID        int64
	LocalID   int64
	Mutation  *pb.SignedEntry
	ExtraData *pb.Committed
}
