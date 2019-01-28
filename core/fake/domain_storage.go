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

package fake

import (
	"context"

	"github.com/google/keytransparency/core/directory"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// DirectoryStorage implements directory.Storage
type DirectoryStorage struct {
	directories map[string]*directory.Directory
}

// NewDirectoryStorage returns a fake dominstorage.Storage
func NewDirectoryStorage() *DirectoryStorage {
	return &DirectoryStorage{
		directories: make(map[string]*directory.Directory),
	}
}

// List returns a list of active directories
func (a *DirectoryStorage) List(ctx context.Context, deleted bool) ([]*directory.Directory, error) {
	ret := make([]*directory.Directory, 0, len(a.directories))
	for _, d := range a.directories {
		ret = append(ret, d)
	}
	return ret, nil
}

// Write adds a new directory.
func (a *DirectoryStorage) Write(ctx context.Context, d *directory.Directory) error {
	a.directories[d.DirectoryID] = d
	return nil
}

// Read returns existing directories.
func (a *DirectoryStorage) Read(ctx context.Context, id string, showDeleted bool) (*directory.Directory, error) {
	d, ok := a.directories[id]
	if !ok || d.Deleted && !showDeleted {
		return nil, status.Errorf(codes.NotFound, "Directory %v not found", id)
	}
	return d, nil
}

// SetDelete deletes or undeletes a directory.
func (a *DirectoryStorage) SetDelete(ctx context.Context, id string, isDeleted bool) error {
	_, ok := a.directories[id]
	if !ok {
		return status.Errorf(codes.NotFound, "Directory %v not found", id)
	}
	a.directories[id].Deleted = isDeleted
	return nil
}

// Delete permanently deletes a directory.
func (a *DirectoryStorage) Delete(ctx context.Context, id string) error {
	_, ok := a.directories[id]
	if !ok {
		return status.Errorf(codes.NotFound, "Directory %v not found", id)
	}
	delete(a.directories, id)
	return nil
}
