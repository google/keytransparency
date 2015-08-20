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

package builder

import (
	"fmt"

	"github.com/google/e2e-key-server/common"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Builder watches a channel and post received elements in the merkle tree.
type Builder struct {
	// update is watched by Build(). Whenever an EntryStorage is received,
	// the appripriate data will be pushed in the tree.
	update chan *corepb.EntryStorage
	// tree contains the merkle tree.
	tree *merkle.Tree
	// saveEntryRelatedInfo is a function handler to
	// storage.Writer.WriteIndexAndEpoch.
	saveEntryRelatedInfo storage.SaveEntryRelatedInfo
}

// New creates an instance of the tree builder with a given channel and a
// handler to save entry related info (commitment timestamp, index, and epoch).
func New(update chan *corepb.EntryStorage, saveEntryRelatedInfo storage.SaveEntryRelatedInfo) *Builder {
	b := &Builder{
		update:               update,
		tree:                 merkle.New(),
		saveEntryRelatedInfo: saveEntryRelatedInfo,
	}
	go b.build()
	return b
}

func (b *Builder) GetTree() *merkle.Tree {
	return b.tree
}

// Build listen to channel Builder.ch and adds a leaf to the tree whenever an
// EntryStorage is received.
func (b *Builder) build() {
	for entryStorage := range b.update {
		// TODO(cesarghali): instead of posting, push to queue.
		if err := b.post(b.tree, entryStorage); err != nil {
			panic(err)
		}
	}
}

// post posts the appropriate data from EntryStorage into the given merkle tree.
func (b *Builder) post(tree *merkle.Tree, entryStorage *corepb.EntryStorage) error {
	// Extract the user's index.
	index, err := index(entryStorage)
	if err != nil {
		return err
	}

	// Add leaf to the merkle tree.
	epoch := merkle.GetCurrentEpoch()
	// Epoch will not advance here (after reading current epoch and before
	// adding the leaf). This is because the builder will post all storage
	// entries into the tree and then, advance the epoch.
	if err := tree.AddLeaf(entryStorage.EntryUpdate, epoch, fmt.Sprintf("%x", index)); err != nil {
		return err
	}

	// Save additional entry related information.
	if err := b.saveEntryRelatedInfo(fmt.Sprintf("%x", index), epoch, common.CommitmentTimestamp(entryStorage.CommitmentTimestamp)); err != nil {
		return err
	}

	return nil
}

// index returns the user's index from EntryStorage.EntryUpdate.Entry.Index.
func index(entryStorage *corepb.EntryStorage) ([]byte, error) {
	// Unmarshal SignedEntryUpdate.
	signedUpdate := new(v2pb.SignedEntryUpdate)
	if err := proto.Unmarshal(entryStorage.EntryUpdate, signedUpdate); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Builder.Build(): Cannot unmarshal SignedEntryUpdate")
	}
	// Unmarshal Entry.
	entry := new(v2pb.Entry)
	if err := proto.Unmarshal(signedUpdate.Entry, entry); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Builder.Build(): Cannot unmarshal Entry")
	}

	return entry.Index, nil
}
