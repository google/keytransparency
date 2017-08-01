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
	"github.com/google/trillian"
	"google.golang.org/grpc"
	"golang.org/x/net/context"
	"github.com/golang/protobuf/ptypes/empty"
)

type adminClient struct{}

func NewTrillianAdminClient() trillian.TrillianAdminClient {
	return adminClient{}
}

// Lists all trees the requester has access to.
func (a *adminClient) ListTrees(ctx context.Context, in *trillian.ListTreesRequest, opts ...grpc.CallOption) (*trillian.ListTreesResponse, error) {
	panic("not implemented")
}

// Retrieves a tree by ID.
func (a *adminClient) GetTree(ctx context.Context, in *trillian.GetTreeRequest, opts ...grpc.CallOption) (*trillian.Tree, error) {
	panic("not implemented")
}

// Creates a new tree.
// System-generated fields are not required and will be ignored if present,
// e.g.: tree_id, create_time and update_time.
// Returns the created tree, with all system-generated fields assigned.
func (a *adminClient) CreateTree(ctx context.Context, in *trillian.CreateTreeRequest, opts ...grpc.CallOption) (*trillian.Tree, error) {
	panic("not implemented")
}

// Updates a tree.
// See Tree for details. Readonly fields cannot be updated.
func (a *adminClient) UpdateTree(ctx context.Context, in *trillian.UpdateTreeRequest, opts ...grpc.CallOption) (*trillian.Tree, error) {
	panic("not implemented")
}

// Soft-deletes a tree.
// A soft-deleted tree may be undeleted for a certain period, after which
// it'll be permanently deleted.
// TODO(codingllama): Provide an undelete RPC.
func (a *adminClient) DeleteTree(ctx context.Context, in *trillian.DeleteTreeRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	panic("not implemented")
}