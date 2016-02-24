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

// Package db describes interfaces into database implementations.
package db

import (
	"golang.org/x/net/context"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

// Queuer submits new mutations to be processed.
type Queuer interface {
	// QueueMutation submits a mutation request for inclusion in the next
	// epoch. The request may fail if this submition is a duplicate or if
	// the mutation fails a correctness check by the mapper.
	QueueMutation(ctx context.Context, index, mutation []byte) error
}

type Mutation struct {
	Index    []byte
	Mutation []byte
	Done     chan error // Returns nil on success. Close on sucess.
}

// Sequencer applies mutations to the persistant map.
type Sequencer interface {
	// The Sequencer object will want to subscribe to the mutation queue.
	// This may be internal to the sequencer implementation?
	Queue() <-chan *Mutation
}
