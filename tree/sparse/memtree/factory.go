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

// Package memtree implements a sparse prefix tree.
// The prefix tree is a binary tree where the path through the tree expresses
// the location of each node.  Each branch expresses the longest shared prefix
// between child nodes. The depth of the tree is the longest shared prefix between
// all nodes.
package memtree

import (
	"github.com/gdbelvin/e2e-key-server/tree"
	"golang.org/x/net/context"
	"log"
)

type TreeFactory struct{}

func NewFactory() *TreeFactory {
	return &TreeFactory{}
}

// FromNeighbors builds a merkle tree from the leaf node and a list of neighbors
// from the root to the leaf

// FromNeighbors builds a merkle tree from the leaf node and a list of neighbors
// from the leaf to just below the root.
func (f *TreeFactory) FromNeighbors(neighbors [][]byte, index, leaf []byte) tree.Sparse {
	ctx := context.Background()
	t := New()
	if leaf != nil {
		if err := t.WriteLeaf(nil, index, leaf); err != nil {
			log.Fatalf("In memory WriteLeaf failed: %v", err)
			return nil
		}
	}

	for i, v := range neighbors {
		if v == nil {
			continue
		}
		depth := len(neighbors) - i // [256, 1]
		neighbor := tree.NeighborIndex(index, depth-1)
		if err := t.SetNode(ctx, neighbor, depth, v); err != nil {
			log.Fatalf("In memory SetNode failed: %v", err)
			return nil
		}
	}
	return t
}
