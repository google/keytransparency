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

package signer

import (
	"log"
	"time"

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/mutator"
	"github.com/google/e2e-key-server/queue"
	"github.com/google/e2e-key-server/tree"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	tspb "github.com/google/e2e-key-server/proto/security_protobuf"
)

// Signer processes mutations, applies them to the sparse merkle tree, and
// signes the sparse tree head.
type Signer struct {
	queue    queue.Queuer
	mutator  mutator.Mutator
	tree     tree.SparseHist
	appender appender.Appender
}

// New creates a new instance of the signer.
func New(queue queue.Queuer, tree tree.SparseHist, mutator mutator.Mutator, appender appender.Appender) *Signer {
	return &Signer{
		queue:    queue,
		mutator:  mutator,
		tree:     tree,
		appender: appender,
	}
}

// Start signing inserts epoch advancement signals into the queue.
func (s *Signer) StartSigning(interval time.Duration) {
	for _ = range time.NewTicker(interval).C {
		s.queue.AdvanceEpoch()
	}
}

// Sequence proceses one item out of the queue. Sequence blocks if the queue
// is empty.
func (s *Signer) Sequence() error {
	return s.queue.Dequeue(s.processMutation, s.CreateEpoch)
}

// StartSequencing loops over Sequence infinitely.
func (s *Signer) StartSequencing() {
	for {
		if err := s.Sequence(); err != nil {
			log.Fatalf("Dequeue failed: %v", err)
		}
	}
}

func (s *Signer) processMutation(index, mutation []byte) error {
	// Get current value.
	ctx := context.Background()
	v, err := s.tree.ReadLeafAt(ctx, index, s.tree.Epoch())
	if err != nil {
		return err
	}

	newV, err := s.mutator.Mutate(v, mutation)
	if err != nil {
		return err
	}

	// Save new value and update tree.
	if err := s.tree.QueueLeaf(ctx, index, newV); err != nil {
		return err
	}
	log.Printf("Sequenced %v", index)
	return nil
}

// CreateEpoch signs the current tree head.
func (s *Signer) CreateEpoch() error {
	ctx := context.Background()
	timestamp := time.Now().Unix()
	epoch, err := s.tree.Commit()
	if err != nil {
		return err
	}
	root, err := s.tree.ReadRootAt(ctx, epoch)
	if err != nil {
		return err
	}

	if _, err := s.appender.GetHLast(ctx); err != nil {
		return err
	}
	head := &ctmap.EpochHead{
		// TODO: set Realm
		IssueTime: &tspb.Timestamp{timestamp, 0},
		Epoch:     timestamp,
		Root:      root,
	}
	headData, err := proto.Marshal(head)
	if err != nil {
		return err
	}
	seh := &ctmap.SignedEpochHead{
		EpochHead: headData,
		// TODO: set Signatures
	}
	signedEpochHead, err := proto.Marshal(seh)
	if err != nil {
		return err
	}
	if err := s.appender.Append(ctx, timestamp, signedEpochHead); err != nil {
		return err
	}
	log.Printf("Created epoch %v. STH: %#x", epoch, root)
	return nil
}
