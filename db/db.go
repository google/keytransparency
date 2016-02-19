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

	corepb "github.com/google/e2e-key-server/proto/security_e2ekeys_core"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

type Mapper interface {
	MapReader
	MapWriter
}

// DB is a distributed database
type Distributed interface {
	Reader
	Writer
	Subscriber
}

type Local interface {
	Reader
	Writer
	// Close releases resources.
	Close()
}

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
}

// Sequencer applies mutations to the persistant map.
type Sequencer interface {
	// The Sequencer object will want to subscribe to the mutation queue.
	// This may be internal to the sequencer implementation?
	Queue() <-chan Mutation
}

type Commitment struct {
	// Commitment key
	Key []byte
	// Commitment value
	Data []byte
}

type Committer interface {
	WriteCommitment(ctx context.Context, commitment, key, value []byte) error
	ReadCommitment(ctx context.Context, commitment []byte) (Commitment, error)
}

// Reader reads values from the sparse tree.
type MapReader interface {
	//ReadNodes(ctx context.Context, indexes [][]byte) ([][]byte, error)
	ReadLeaf(ctx context.Context, index []byte) ([]byte, error)
}

type Node struct {
	Index []byte
	Value []byte
}

type MapWriter interface {
	WriteNodes(ctx context.Context, nodes []Node) error
	WriteLeaf(ctx context.Context, index, leaf []byte) error
}

type Reader interface {
	// ReadUpdate reads a EntryStroage from the storage.
	ReadUpdate(ctx context.Context, primaryKey int64) (*corepb.EntryStorage, error)
	// ReadEpochInfo reads an EpochInfo from the storage
	ReadEpochInfo(ctx context.Context, primaryKey int64) (*corepb.EpochInfo, error)
}

type Writer interface {
	// WriteUpdate inserts a new EntryStorage in the storage. Fails if the
	// row already exists.
	WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error
	// WriteEpochInfo writes the epoch information in the storage.
	WriteEpochInfo(ctx context.Context, primaryKey int64, epochInfo *corepb.EpochInfo) error
}

type Subscriber interface {
	// SubscribeUpdates subscribes an update channel. All EntryStorage will
	// be transmitted on all subscribed channels.
	SubscribeUpdates(ch chan *corepb.EntryStorage)
	// SubscribeEpochInfo subscribes an epoch info channel. All EpochInfo
	// will be transmitted on all subscribed channels.
	SubscribeEpochInfo(ch chan *corepb.EpochInfo)
}
