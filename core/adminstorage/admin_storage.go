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

// Package admin stores multi-tennancy configuration information.
package adminstorage

import (
	"context"

	"github.com/golang/protobuf/proto"
	"github.com/google/trillian/crypto/keyspb"
)

// Domain stores configuration information for a single Key Transparency instance.
type Domain struct {
	Domain string
	MapID  int64
	LogID  int64

	VRF     *keyspb.PublicKey
	VRFPriv proto.Message
	Deleted bool
}

// Storage is an interface for storing multi-tennant configuration information.
type Storage interface {
	// List returns the full list of domains.
	List(ctx context.Context, deleted bool) ([]*Domain, error)
	// Write stores a new instance to storage.
	Write(ctx context.Context, ID string, mapID, LogID int64, vrfPublicDER []byte, wrappedVRF proto.Message) error
	// Read a configuration from storage.
	Read(ctx context.Context, ID string, showDeleted bool) (*Domain, error)
	// Delete and undelete.
	SetDelete(ctx context.Context, ID string, isDeleted bool) error
}
