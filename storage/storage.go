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

// Package storage provides an API to persistant storage.
package storage

import (
	"golang.org/x/net/context"

	corepb "github.com/google/e2e-key-server/proto/core"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

type ConsistentStorage interface {
	Reader
	Writer
	Subscriber
}

type LocalStorage interface {
	Reader
	Writer
	Closer
}

type Reader interface {
	// ReadUpdate reads a EntryStroage from the storage.
	ReadUpdate(ctx context.Context, primaryKey uint64) (*corepb.EntryStorage, error)
	// ReadEpochInfo reads an EpochInfo from the storage
	ReadEpochInfo(ctx context.Context, primaryKey uint64) (*corepb.EpochInfo, error)
}

type Writer interface {
	// WriteUpdate inserts a new EntryStorage in the storage. Fails if the
	// row already exists.
	WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error
	// WriteEpochInfo writes the epoch information in the storage.
	WriteEpochInfo(ctx context.Context, primaryKey uint64, epochInfo *corepb.EpochInfo) error
}

type Subscriber interface {
	// SubscribeUpdates subscribes an update channel. All EntryStorage will
	// be transmitted on all subscribed channels.
	SubscribeUpdates(ch chan *corepb.EntryStorage)
	// SubscribeEpochInfo subscribes an epoch info channel. All EpochInfo
	// will be transmitted on all subscribed channels.
	SubscribeEpochInfo(ch chan *corepb.EpochInfo)
}

type Closer interface {
	// Close closes the storage instance and release all resources.
	Close()
}
