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
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	"github.com/google/keytransparency/core/water"
)

var (
	// MaxMutationSize represent the maximum allowed mutation size in bytes.
	MaxMutationSize = 16 * 1024
	// ErrReplay occurs when two mutations acting on the same entry & revision
	// occur.
	ErrReplay = status.Errorf(codes.FailedPrecondition, "mutation replay")
	// ErrSize occurs when the mutation size is larger than the allowed upper
	// bound.
	ErrSize = status.Errorf(codes.InvalidArgument, "mutation: too large")
	// ErrPreviousHash occurs when the mutation the hash of the previous
	// entry provided in the mutation does not match the previous entry
	// itself.
	ErrPreviousHash = status.Errorf(codes.InvalidArgument, "mutation: previous entry hash does not match the hash provided in the mutation")
	// ErrInvalidSig occurs when either the current or previous update entry
	// signature verification fails.
	ErrInvalidSig = status.Errorf(codes.InvalidArgument, "mutation: invalid signature")
	// ErrUnauthorized occurs when the mutation has not been signed by a key in the
	// previous entry.
	ErrUnauthorized = status.Errorf(codes.PermissionDenied, "mutation: unauthorized")
)

// VerifyMutationFn verifies that a mutation is internally consistent.
type VerifyMutationFn func(mutation *pb.SignedEntry) error

// LogMessage represents a change to a user, and associated data.
type LogMessage struct {
	LogID     int64
	ID        water.Mark
	LocalID   int64
	CreatedAt time.Time
	Mutation  *pb.SignedEntry
	ExtraData *pb.Committed
}
