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
	pb "github.com/google/e2e-key-server/proto/v2"
)

// TODO: put this somewhere better
type Epoch int64

// TODO: Make this a protobuf
type ClusterNodeState struct {
	NodeId            string
	NewestSTR         *pb.SignedTreeRoot
	CurrentServingSTR *pb.SignedTreeRoot
	Hostname          string
	Port              int32
}

type ConsistentStore interface {
	// Returns a codes.AlreadyExists error if a promise for the same (user_id,
	// key_id) already exists.
	InsertPromise(promise *pb.KeyPromise) error

	// Creates a new epoch, assigning the outstanding promises to that epoch. (If
	// some promises are being inserted concurrently, they may or may not be
	// included.)
	// If the given epoch is not the next epoch, this returns an error. This is
	// mostly to prevent accidental concurrent creation of new STRs.
	CreateNewEpoch(epoch Epoch) error

	// Watches for promises for all users after a particular epoch (i.e. all
	// pending updates that were not included in that epoch), sending them to the
	// receiver chan. Will immediately send all existing updates and then send new
	// promises as they trickle in. The function blocks, so it should be called in
	// its own goroutine. If the stop channel is closed, the watch ends and the
	// function returns.
	// Returns a codes.OutOfRange error if that epoch is either not yet stored or
	// not stored anymore in the consistent storage. If a node uses its current
	// serving epoch and gets OutOfRange, it knows it's out of date.
	WatchPendingUpdates(after Epoch, receiver chan *pb.KeyPromise,
		stop chan struct{}) error

	GetUpdatesInEpoch(epoch Epoch) ([]*pb.KeyPromise, error)

	// Inserts a new signed tree root, which should contain all the updates
	// assigned to its epoch.
	InsertNewestSTR(str *pb.SignedTreeRoot) error

	GetNewestSTR() (*pb.SignedTreeRoot, error)

	// Sends the newest STR, followed by updates as they come, to the receiver
	// chan. If the stop channel is closed, the watch ends and the function
	// returns.
	WatchNewestSTR(receiver chan *pb.SignedTreeRoot, stop chan struct{}) error

	GetServingSTR() (*pb.SignedTreeRoot, error)

	SetServingSTR(str *pb.SignedTreeRoot) error

	// Sends the current serving STR, followed by updates as they come, to the
	// receiver chan. If the stop channel is closed, the watch ends and the
	// function returns.
	WatchServingSTR(receiver chan *pb.SignedTreeRoot, stop chan struct{}) error

	// Updates the current node's state.
	SetClusterNodeState(state *ClusterNodeState) error

	// Gets the current node's state.
	GetClusterNodeState() (*ClusterNodeState, error)

	// Sends all the current cluster node states, followed by updates as they
	// come, to the receiver chan. If the stop channel is closed, the watch ends
	// and the function returns.
	WatchClusterNodeStates(receiver chan *ClusterNodeState,
		stop chan struct{}) error

	// Removes pending updates that have been included in the current serving STR.
	CleanupOldEntries() error
}
