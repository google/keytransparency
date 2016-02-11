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
	"log"
	"math"
	"sync/atomic"

	"github.com/google/e2e-key-server/db"
	"github.com/google/e2e-key-server/epoch"
	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/utils/queue"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	corepb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_core"
	v2pb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_v2"
)

// Builder watches a channel and posts received elements in the merkle tree.
type Builder struct {
	// updates is watched by handleUpdates(). Whenever an EntryStorage is
	// received, the appripriate data will be pushed in the tree.
	updates chan *corepb.EntryStorage
	// epochInfo is watched by handleEpochInfo(). Whenever an EpochInfo is
	// received, it triggers creating a new epoch.
	epochInfo chan *corepb.EpochInfo
	// t contains the merkle tree.
	tree *merkle.Tree
	// distributed is a distributed database
	distributed db.Distributed
	// local is a local db cache.
	local db.Local
	// epoch is an instance of merkle.Epoch.
	epoch *epoch.Epoch
	// queue is a goroutine safe queue.
	queue *queue.Queue
	// Contains the timestamp of the last update to be included in the new
	// epoch.
	lastCommitmentTS uint64
}

// New creates an instance of the tree builder with a given channel.
// The Builder created instance will be ready to use by the signer.
func New(distributed db.Distributed, local db.Local) *Builder {
	b := &Builder{
		updates:     make(chan *corepb.EntryStorage),
		tree:        merkle.New(),
		local:       local,
		distributed: distributed,
		epoch:       epoch.New(),
		queue:       queue.New(),
	}

	// Subscribe the updates channel.
	distributed.SubscribeUpdates(b.updates)
	go b.handleUpdates()

	return b
}

func (b *Builder) ListenForEpochUpdates() {
	// Subscribe the epochInfo channel.
	b.distributed.SubscribeEpochInfo(b.epochInfo)
	go b.handleEpochInfo()
}

// handleUpdates listens to channel Builder.ch and adds a leaf to the tree
// whenever an EntryStorage is received.
func (b *Builder) handleUpdates() {
	for entryStorage := range b.updates {
		// Local ignores context, so nil is passed here.
		if err := b.local.WriteUpdate(nil, entryStorage); err != nil {
			log.Fatalf("Failed to save update to disk: %v", err)
			// TODO: Implement a failure mode.
		}

		b.queue.Enqueue(entryStorage)
		atomic.StoreUint64(&b.lastCommitmentTS, entryStorage.CommitmentTimestamp)
	}
}

// handleEpochInfo triggers building an new epoch after the signer creates its
// own.
func (b *Builder) handleEpochInfo() {
	for info := range b.epochInfo {
		localEpochHead, err := b.CreateEpoch(info.LastCommitmentTimestamp, false)
		if err != nil {
			log.Fatalf("Failed to create epoch from timestamp %v: %v",
				info.LastCommitmentTimestamp, err)
		}

		// Verify that the create epoch matches the one created by the
		// signer.
		signerEpochHead := new(v2pb.EpochHead)
		if err := proto.Unmarshal(info.GetSignedEpochHead().EpochHead, signerEpochHead); err != nil {
			log.Fatalf("Failed to unmarshal epoch head: %v", err)
		}

		if !bytes.Equal(signerEpochHead.Root, localEpochHead.Root) {
			// TODO: implement failuer recovery.
			log.Fatalf("Created epoch does not match the signer epoch")
		}

		// Save the signed epoch head in local db.
		if err := b.local.WriteEpochInfo(nil, b.epoch.Building(), info); err != nil {
			log.Fatalf("Failed to write EpochInfo: %v", err)
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
	// adding the leaf). This is because the builder will post all db
	// entries into the tree and then, advance the epoch.
	if err := tree.AddLeaf(entryStorage.GetSignedEntryUpdate().NewEntry, epoch, index, entryStorage.CommitmentTimestamp); err != nil {
		return err
	}

	return nil
}

// CreateEpoch posts all StorageEntry in Builder.queue to the merkle tree and
// and returns the corresponding EpochHead.
func (b *Builder) CreateEpoch(lastCommitmentTS uint64, advance bool) (*v2pb.EpochHead, error) {
	// Create the new epoch in the tree.
	if err := b.tree.AddRoot(b.epoch.Building()); err != nil {
		return nil, err
	}

	// Read all EntryStorage in the queue that have
	// timestamp less than lastCommitmentTS and post them to
	// the tree.
	for b.queue.Size() > 0 {
		v := b.queue.Peek()

		entryStorage := v.(*corepb.EntryStorage)
		// If the EntryStorage element in the queue has a timestamp
		// larger than the last one that should included in ths epoch,
		// break the loop.
		if entryStorage.CommitmentTimestamp > lastCommitmentTS {
			break
		}

		// Dequeue will always return the same element as Peek. The
		// reason is because this thread is the only thread that reads
		// from the queue. If in the future multiple threads will be
		// reading from the queue, this for loop should be synchronized
		// by a mutex.
		b.queue.Dequeue()

		// Post v to the tree.
		if err := b.post(b.tree, entryStorage); err != nil {
			return nil, err
		}
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
	if epoch == math.MaxUint64 {
		epoch = b.epoch.Serving()
	}
	return b.tree.AuditPath(epoch, index)
}

// GetSignedEpochHeads
func (b *Builder) GetSignedEpochHeads(ctx context.Context, epoch uint64) ([]*v2pb.SignedEpochHead, error) {
	// Swap out cache logic for just querying the database.
	if epoch == math.MaxUint64 {
		epoch = b.epoch.Serving()
	}

	info, err := b.local.ReadEpochInfo(ctx, epoch)
	if err != nil {
		return nil, err
	}

	return []*v2pb.SignedEpochHead{info.GetSignedEpochHead()}, nil
}

// Updates returns the updates channel.
func (b *Builder) Updates() chan *corepb.EntryStorage {
	return b.updates
}

// EpochInfo returnes the epochInfo channel.
func (b *Builder) EpochInfo() chan *corepb.EpochInfo {
	return b.epochInfo
}

// LastCommitmentTimestamp returns the last commitment timestamp seen.
func (b *Builder) LastCommitmentTimestamp() uint64 {
	return atomic.LoadUint64(&b.lastCommitmentTS)
}

func (b *Builder) Close() {
	if b.updates != nil {
		close(b.updates)
	}
	if b.epochInfo != nil {
		close(b.epochInfo)
	}
}
