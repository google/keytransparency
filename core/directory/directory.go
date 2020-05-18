// Copyright 2017 Google Inc. All Rights Reserved.
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

// Package directory stores multi-tenancy configuration information.
package directory

import (
	"context"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	tpb "github.com/google/trillian"
	"github.com/google/trillian/crypto/keyspb"
)

// Directory stores configuration information for a single Key Transparency instance.
type Directory struct {
	DirectoryID string
	Map         *tpb.Tree
	Log         *tpb.Tree
	VRF         *keyspb.PublicKey

	VRFPriv                  proto.Message
	MinInterval, MaxInterval time.Duration
	// TODO(gbelvin): specify mutation function
	Deleted          bool
	DeletedTimestamp time.Time
}

// Storage is an interface for storing multi-tenant configuration information.
type Storage interface {
	// List returns the full list of directories.
	List(ctx context.Context, deleted bool) ([]*Directory, error)
	// Write stores a new instance to storage.
	Write(ctx context.Context, d *Directory) error
	// Read a configuration from storage.
	Read(ctx context.Context, directoryID string, showDeleted bool) (*Directory, error)
	// Soft-delete or undelete the directory
	SetDelete(ctx context.Context, directoryID string, isDeleted bool) error
	// HardDelete the directory.
	Delete(ctx context.Context, directoryID string) error
}
