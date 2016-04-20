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

	"github.com/gdbelvin/e2e-key-server/appender"
	"github.com/gdbelvin/e2e-key-server/db"
	"github.com/gdbelvin/e2e-key-server/mutator"
	"github.com/gdbelvin/e2e-key-server/tree"
	"golang.org/x/net/context"

	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
	tspb "github.com/gdbelvin/e2e-key-server/proto/security_protobuf"
	proto "github.com/golang/protobuf/proto"
)

// Signer is the object responsible for triggering epoch creation and signing
// the epoch head once created.
type Signer struct {
	// Sequencer listens to new items on the queue and saves them.
	sequencer db.Sequencer
	mutator   mutator.Mutator
	tree      tree.Sparse
	appender  appender.Appender
}

// New creates a new instance of the signer.
func New(sequencer db.Sequencer, tree tree.Sparse, mutator mutator.Mutator, appender appender.Appender) (*Signer, error) {
	// Create a signer instance.
	s := &Signer{
		sequencer: sequencer,
		mutator:   mutator,
		tree:      tree,
		appender:  appender,
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
	v, err := s.tree.ReadLeaf(ctx, index)
	if err != nil {
		return err
	}

	newV, err := s.mutator.Mutate(v, mutation)
	if err != nil {
		return err
	}

	// Save new value and update tree.
	if err := s.tree.WriteLeaf(ctx, index, newV); err != nil {
		return err
	}
	return nil
}

// CreateEpoch signs the current tree head.
func (s *Signer) CreateEpoch() {
	ctx := context.Background()
	timestamp := time.Now().Unix()
	root, err := s.tree.ReadRoot(ctx)
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
