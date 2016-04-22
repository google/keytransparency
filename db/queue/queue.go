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

// Package queue describes a queue.
package queue

import (
	"log"

	"github.com/coreos/etcd/raft/raftpb"
	"golang.org/x/net/context"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

// Queuer submits new mutations to be processed.
type Queuer interface {
	// Queue submits a mutation request for inclusion in the next
	// epoch. The request may fail if this submition is a duplicate or if
	// the mutation fails a correctness check by the mapper.
	Queue(ctx context.Context, index, mutation []byte) error

	// The DeQueuer object will want to subscribe to the mutation queue.
	// This may be internal to the sequencer implementation?
	Dequeue() <-chan *Mutation
}

type Mutation struct {
	kv
	Done chan error // Returns nil on success. Close on sucess.
}

type kv struct {
	Key []byte
	Val []byte
}
