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

package grpcc

import (
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
	spb "github.com/google/key-transparency/impl/proto/keytransparency_v1_service"
)

// Dialer represents a gRPC dialer.
type Dialer struct {
	cli spb.KeyTransparencyServiceClient
}

// New creates a new gRPC dialer instance.
func New(cc *grpc.ClientConn) *Dialer {
	return &Dialer{spb.NewKeyTransparencyServiceClient(cc)}
}

// Get returns an entry if it exists, and nil if it does not.
func (c *Dialer) Get(ctx context.Context, in *tpb.GetEntryRequest, connOpts ...interface{}) (*tpb.GetEntryResponse, error) {
	return c.cli.GetEntry(ctx, in)
}

// List returns a list of profiles starting and ending at given epochs.
func (c *Dialer) List(ctx context.Context, in *tpb.ListEntryHistoryRequest, connOpts ...interface{}) (*tpb.ListEntryHistoryResponse, error) {
	return c.cli.ListEntryHistory(ctx, in)
}

// Update updates a user's profile.
func (c *Dialer) Update(ctx context.Context, in *tpb.UpdateEntryRequest, connOpts ...interface{}) (*tpb.UpdateEntryResponse, error) {
	return c.cli.UpdateEntry(ctx, in)
}
