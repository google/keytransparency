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

package merkle

import (
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	internalpb "github.com/google/e2e-key-server/proto/internal"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Builder watches a channel and post received elements in the merkle tree.
type Builder struct {
	// ch is watched by Build(). Whenever an EntryStorage is received, the
	// appripriate data will be pushed in the tree.
	ch chan interface{}
	// t contains the merkle tree.
	t *Tree
	// quit is watched by Build(). Whenever anything is received, Build will
	// stop.
	quit chan int
}

// Create creates an instance of the tree builder with a given channel.
func Create(c chan interface{}) Builder {
	return Builder{
		ch:   c,
		t:    New(),
		quit: make(chan int, 1),
	}
}

func (b *Builder) GetTree() Tree {
	return *b.t
}

// Build listen to channel Builder.ch and adds a leaf to the tree whenever an
// EntryStorage is received.
func (b *Builder) Build() {
	for {
		select {
		// TODO(cesarghali): instead of posting, push to queue.
		case received := <-b.ch:
			// entry should be of type EntryStorage, if not skip it.
			es, ok := received.(*internalpb.EntryStorage)
			if es != nil && ok {
				if err := post(b.t, es); err != nil {
					panic(err)
				}
			}
		case <-b.quit:
			// Stop building
			close(b.quit)
			return
		}
	}
}

// post posts the appropriate data from EntryStorage into the given merkle tree.
func post(t *Tree, es *internalpb.EntryStorage) error {
	// Unmarshal SignedEntryUpdate.
	seu := new(v2pb.SignedEntryUpdate)
	if err := proto.Unmarshal(es.EntryUpdate, seu); err != nil {
		return grpc.Errorf(codes.Internal, "Builder.Build(): Cannot unmarshal SignedEntryUpdate")
	}
	// Unmarshal Entry.
	e := new(v2pb.Entry)
	if err := proto.Unmarshal(seu.Entry, e); err != nil {
		return grpc.Errorf(codes.Internal, "Builder.Build(): Cannot unmarshal Entry")
	}

	// Add leaf to the merkle tree.
	if err := t.AddLeaf(es.EntryUpdate, Epoch(es.Epoch), fmt.Sprintf("%x", e.Index)); err != nil {
		return err
	}

	return nil
}

// Stop writes 0 to the quit channel. This will stop the builder.
func (b *Builder) Stop() {
	b.quit <- 0
}
