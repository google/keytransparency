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

// Package merkle implements a time series prefix tree. Each epoch has its own
// prefix tree. By default, each new epoch is equal to the contents of the
// previous epoch.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.
package tree

import (
	"golang.org/x/net/context"
)

// Sparse is a sparse merkle tree
type Sparse interface {
	ReadRoot(ctx context.Context) ([]byte, error)
	ReadLeaf(ctx context.Context, index []byte) ([]byte, error)
	WriteLeaf(ctx context.Context, index, leaf []byte) error
	Neighbors(ctx context.Context, index []byte) ([][]byte, error)
}

// SparseHist is a temporal sparse merkle tree
type SparseHist interface {
	Sparse
	WriteLeafAt(ctx context.Context, index, leaf []byte, epoch int64) error
	NeighborsAt(ctx context.Context, epoch int64, index []byte) ([][]byte, error)
}
