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

type BasicStorage interface {
	// InsertLogTableRow ensures that there is a valid directory entry for
	// our data.
	InsertLogTableRow(ctx context.Context)
	// UpdateEntryStorage updates a UserEntryStorage row. Fails if the row
	// does not already exist.
	UpdateEntryStorage(ctx context.Context, profile *internalpb.EntryStorage, vuf string) error
	// InsertEntryStorage inserts a new UserEntryStorage row. Fails if the
	// row already exists.
	InsertEntryStorage(ctx context.Context, profile *internalpb.EntryStorage, vuf string) error
	// DeleteEntryStorage deletes a profile.
	DeleteEntryStorage(ctx context.Context, vuf string) error
	// ReadEntryStorage reads a profile.
	ReadEntryStorage(ctx context.Context, vuf string) (*internalpb.EntryStorage, error)
	// VUFExists returns true if an entry already exists for the given VUF,
	// and false otherwise.
	EntryStorageExists(ctx context.Context, vuf string) bool
}

// TODO(cesarghali): bring back ConkisStorage and make it compatible with the
// new proto.
