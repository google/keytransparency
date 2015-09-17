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
	corepb "github.com/google/e2e-key-server/proto/core"
	context "golang.org/x/net/context"
)

const (
	// ChannelSize is the buffer size of the channel used to send an
	// EntryStorage to the tree builder.
	ChannelSize = 100
)

type ConsistentStorage interface {
	Reader
	Writer
	Watchable
	Helper
}

type LocalStorage interface {
	Reader
	Writer
	Closer
}

type Reader interface {
	// ReadUpdate reads a EntryStroage from the storage.
	ReadUpdate(ctx context.Context, primaryKey uint64) (*corepb.EntryStorage, error)
}

type Writer interface {
	// WriteUpdate inserts a new EntryStorage in the storage. Fails if the
	// row already exists.
	WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error
	// WriteEpochInfo writes the epoch information in the storage.
	WriteEpochInfo(ctx context.Context, primaryKey uint64, epochInfo *corepb.EpochInfo) error
}

type Closer interface {
	// Close closes the storage instance and release all resources.
	Close()
}

type Watchable interface {
	// BuilderUpdates returns a channel containing EntryStorage entries,
	// which are pushed into the channel whenever an EntryStorage is written
	// in the storage. This channel is watched by the builder.
	BuilderUpdates() chan *corepb.EntryStorage
	// SignerUpdates returns a channel containing EntryStorage entries,
	// which are pushed into the channel whenever an EntryStorage is written
	// in the storage. This channel is watched by the signer.
	SignerUpdates() chan *corepb.EntryStorage
	// EpochInfo returns a channel that is used to transmit EpochInfo to the
	// builder once the signer creates a new epoch.
	EpochInfo() chan *corepb.EpochInfo
}

type Helper interface {
	// LastCommitmentTimestamp returns the timestamp of the last update that
	// should included in the new epoch.
	LastCommitmentTimestamp() uint64
}
