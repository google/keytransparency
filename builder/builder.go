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
	"bytes"
	"sync"

	"github.com/google/e2e-key-server/epoch"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Builder watches a channel and post received elements in the merkle tree.
type Builder struct {
	// updates is watched by build(). Whenever an EntryStorage is received,
	// the appripriate data will be pushed in the tree.
	updates chan *corepb.EntryStorage
	// epochInfo is watched by trigger(). Whenever an EpochInfo is received,
	// it triggers creating a new epoch.
	epochInfo chan *corepb.EpochInfo
	// t contains the merkle tree.
	tree *merkle.Tree
	// store is an instance to LocalStorage.
	store storage.LocalStorage
	// epoch is an instance of merkle.Epoch.
	epoch *epoch.Epoch
	// queue stores the storage entries arrived on the channel
	queue []*corepb.EntryStorage
	// mu syncronizes access to queue.
	mu sync.Mutex
}

// New creates an instance of the tree builder with a given channel.
func New(updates chan *corepb.EntryStorage, store storage.LocalStorage) *Builder {
	b := &Builder{
		updates: updates,
		tree:    merkle.New(),
		store:   store,
		epoch:   epoch.New(),
	}
	go b.build()
	go b.trigger()
	return b
}

// build listens to channel Builder.ch and adds a leaf to the tree whenever an
// EntryStorage is received.
func (b *Builder) build() {
	for entryStorage := range b.updates {
		// LocalStorage ignores context, so nil is passed here.
		if err := b.store.WriteUpdate(nil, entryStorage); err != nil {
			// TODO: for now just panic. However, if Write fails, it
			//       means something very wrong happened and we
			//       should implement some DB failure recovery
			//       mechanism.
			panic(err)
		}

		b.mu.Lock()
		b.queue = append(b.queue, entryStorage)
		b.mu.Unlock()
	}
}

// trigger triggers building an new epoch after the signer creates its own.
func (b *Builder) trigger() {
	for info := range b.epochInfo {
		createdEpochHead, err := b.CreateEpoch(info.LastCommitmentTimestamp, false)
		if err != nil {
			panic(err)
		}

		// Verify that the create epoch matches the one created by the
		// signer.
		signerEpochHead := new(v2pb.EpochHead)
		if err := proto.Unmarshal(info.GetSignedEpochHead().EpochHead, signerEpochHead); err != nil {
			panic(err)
		}

		if !bytes.Equal(signerEpochHead.Root, createdEpochHead.Root) {
			// TODO: implement failuer recovery.
			panic("Created epoch does not match the signer epoch")
		}

		// Save the created signed epoch head in local storage.
		// TODO(cesarghali): fill IssueTime and PreviousEpochHeadHash.
		epochHeadData, err := proto.Marshal(createdEpochHead)
		if err != nil {
			panic(err)
		}
		signedEpochHead := &v2pb.SignedEpochHead{
			EpochHead: epochHeadData,
			// TODO(cesarghali): fill Signatures
		}
		info := &corepb.EpochInfo{
			SignedEpochHead:         signedEpochHead,
			LastCommitmentTimestamp: info.LastCommitmentTimestamp,
		}
		if err := b.store.WriteEpochInfo(nil, b.epoch.Building(), info); err != nil {
			panic(err)
		}

		// Advance the epoch.
		b.epoch.Advance()
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
	epoch := b.epoch.Building()
	// Epoch will not advance here (after reading current epoch and before
	// adding the leaf). This is because the builder will post all storage
	// entries into the tree and then, advance the epoch.
	if err := tree.AddLeaf(entryStorage.GetSignedEntryUpdate().NewEntry, epoch, index, entryStorage.CommitmentTimestamp); err != nil {
		return err
	}

	return nil
}

// CreateEpoch posts all StorageEntry in Builder.queue to the merkle tree and
// and returns the corresponding EpochHead.
func (b *Builder) CreateEpoch(lastCommitmentTS uint64, advance bool) (*v2pb.EpochHead, error) {
	// If EntryStorage is empty, create an empty epoch in the tree.
	// Otherwise, post all EntryStorage in the queue on the tree.
	if len(b.queue) == 0 {
		// Create the new epoch in the tree.
		if err := b.tree.AddRoot(b.epoch.Building()); err != nil {
			return nil, err
		}
	} else {
		// Read all EntryStorage in the queue that have
		// timestamp less than lastCommitmentTS and post them to
		// the tree.
		var i int
		var v *corepb.EntryStorage
		for i, v = range b.queue {
			if v.CommitmentTimestamp > lastCommitmentTS {
				break
			}

			// Post v to the tree.
			if err := b.post(b.tree, v); err != nil {
				return nil, err
			}
		}

		// Remove already processed StorageEntry from the queue
		b.queue = b.queue[i+1:]
	}

	root, err := b.tree.Root(b.epoch.Building())
	if err != nil {
		return nil, err
	}

	epochHead := &v2pb.EpochHead{
		// TODO: set Realm
		Epoch: b.epoch.Building(),
		Root:  root,
	}

	// Advance the epoch.
	if advance {
		b.epoch.Advance()
	}

	return epochHead, nil
}

// index returns the user's index from EntryStorage.SignedEntryUpdate.NewEntry.Index.
func index(entryStorage *corepb.EntryStorage) ([]byte, error) {
	// Unmarshal Entry.
	entry := new(v2pb.Entry)
	if err := proto.Unmarshal(entryStorage.GetSignedEntryUpdate().NewEntry, entry); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Builder.Build(): Cannot unmarshal Entry")
	}

	return entry.Index, nil
}

// AuditPath is a wrapper to Tree.AuditPath.
func (b *Builder) AuditPath(epoch uint64, index []byte) ([][]byte, uint64, error) {
	if epoch == 0 {
		epoch = b.epoch.Serving()
	}
	return b.tree.AuditPath(epoch, index)
}

// GetSignedEpochHeads
func (b *Builder) GetSignedEpochHeads(ctx context.Context, epoch uint64) ([]*v2pb.SignedEpochHead, error) {
	if epoch == 0 {
		epoch = b.epoch.Serving()
	}

	info, err := b.store.ReadEpochInfo(ctx, epoch)
	if err != nil {
		return nil, err
	}

	return []*v2pb.SignedEpochHead{info.GetSignedEpochHead()}, nil
}
