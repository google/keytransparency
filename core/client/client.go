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

package client

import (
	"golang.org/x/net/context"

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

// Conn defines client APIs regardless of the underlying used connection, e.g.,
// gRPC or HTTP.
type Conn interface {
	// Get returns an entry if it exists, and nil if it does not.
	Get(ctx context.Context, in *tpb.GetEntryRequest, connOpts ...interface{}) (*tpb.GetEntryResponse, error)
	// List returns a list of profiles starting and ending at given epochs.
	List(ctx context.Context, in *tpb.ListEntryHistoryRequest, connOpts ...interface{}) (*tpb.ListEntryHistoryResponse, error)
	// Update updates a user's profile.
	Update(ctx context.Context, in *tpb.UpdateEntryRequest, connOpts ...interface{}) (*tpb.UpdateEntryResponse, error)
}
