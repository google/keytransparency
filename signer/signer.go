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
	"github.com/google/e2e-key-server/db"
	"github.com/google/e2e-key-server/mutator"
	"github.com/google/e2e-key-server/tree"
	"golang.org/x/net/context"

	proto "github.com/golang/protobuf/proto"
	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
	tspb "github.com/google/e2e-key-server/proto/security_protobuf"
)

// Signer is the object responsible for triggering epoch creation and signing
// the epoch head once created.
type Signer struct {
	// Sequencer listens to new items on the queue and saves them.
	sequencer db.Sequencer
	mutator   mutator.Mutator
	tree      tree.SparseHist
	appender  appender.Appender
	epoch     int64
}

// New creates a new instance of the signer.
func New(sequencer db.Sequencer, tree tree.SparseHist, mutator mutator.Mutator, appender appender.Appender) (*Signer, error) {
	// Create a signer instance.
	s := &Signer{
		sequencer: sequencer,
		mutator:   mutator,
		tree:      tree,
		appender:  appender,
		// TODO: Read current epoch out of database.
	}

	return s, nil
}

func (s *Signer) StartSequencing() {
	go func() {
		for m := range s.sequencer.Queue() {
			err := s.sequenceOne(m.Index, m.Mutation)
			m.Done <- err
		}
	}()
}

func (s *Signer) Sequence() {
	m := <-s.sequencer.Queue()
	s.sequenceOne(m.Index, m.Mutation)
}

func (s *Signer) StartSigning(interval time.Duration) {
	go func() {
		for _ = range time.NewTicker(interval).C {
			s.CreateEpoch()
		}
	}()
}

func (s *Signer) sequenceOne(index, mutation []byte) error {
	// Get current value.
	ctx := context.Background()
	v, err := s.tree.ReadLeafAt(ctx, index, s.epoch)
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
	return nil
}

// CreateEpoch signs the current tree head.
func (s *Signer) CreateEpoch() {
	ctx := context.Background()
	timestamp := time.Now().Unix()
	epoch, err := s.tree.Commit()
	if err != nil {
		log.Fatalf("Failed to create epoch: %v", err)
	}
	s.epoch = epoch
	root, err := s.tree.ReadRootAt(ctx, s.epoch)
	if err != nil {
		log.Fatalf("Failed to create epoch: %v", err)
	}

	prevHash, err := s.appender.GetHLast(ctx)
	if err != nil {
		log.Fatalf("Failed to get previous epoch: %v", err)
	}
	head := &ctmap.EpochHead{
		// TODO: set Realm
		IssueTime:    &tspb.Timestamp{timestamp, 0},
		PreviousHash: prevHash,
		Epoch:        timestamp,
		Root:         root,
	}
	headData, err := proto.Marshal(head)
	if err != nil {
		log.Fatalf("Failed to marshal epoch: %v", err)
	}
	seh := &ctmap.SignedEpochHead{
		EpochHead: headData,
		// TODO: set Signatures
	}
	signedEpochHead, err := proto.Marshal(seh)
	if err != nil {
		log.Fatalf("Failed to marshal signed epoch: %v", err)
	}
	if err := s.appender.Append(ctx, timestamp, signedEpochHead); err != nil {
		log.Fatalf("Failed to write SignedHead: %v", err)
	}
}

// Stop stops the signer and release all associated resource.
func (s *Signer) Stop() {
}
