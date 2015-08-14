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

// Package storage provides an API to persistant storage, implemented with spanner.
package storage

import (
	//"time"

	internalpb "github.com/google/e2e-key-server/proto/internal"
	context "golang.org/x/net/context"
)

type DataStore interface {
	Reader
	Writer
	Watcher
}

type Reader interface {
	// Read reads a EntryStroage from the storage.
	Read(ctx context.Context, vuf string) (*internalpb.EntryStorage, error)
}

type Writer interface {
	// Write inserts a new EntryStorage in the storage. Fails if the row
	// already exists.
	Write(ctx context.Context, entry *internalpb.EntryStorage, vuf string) error
}

type Watcher interface {
	// GetChannel returns a channel.
	GetChannel() chan interface{}
	// CloseChannel closes the current channel.
	CloseChannel()
}

// TODO(cesarghali): bring back ConkisStorage and make it compatible with the
// new proto.
