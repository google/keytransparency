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
	tspb "github.com/google/e2e-key-server/proto/google_protobuf"
	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
)

// Signer is the object responsible for triggering epoch creation and signing
// the epoch head once created.
type Signer struct {
	// Sequencer listens to new items on the queue and saves them.
	sequencer db.Sequencer
	mutator   mutator.Mutator
	tree      tree.Sparse
	sth       appender.Appender

	// ticker ticks everytime a new epoch should be created.
	ticker *time.Ticker
}

// New creates a new instance of the signer.
func New(sequencer db.Sequencer, tree tree.Sparse, mutator mutator.Mutator, appender appender.Appender, seconds uint) (*Signer, error) {
	// Create a signer instance.
	s := &Signer{
		sequencer: sequencer,
		mutator:   mutator,
		tree:      tree,
		sth:       appender,
		ticker:    time.NewTicker(time.Second * time.Duration(seconds)),
	}
	go s.createEpoch()
	go s.sequence()
	return s, nil
}

func (s *Signer) sequence() {
	for m := range s.sequencer.Queue() {
		s.sequenceOne(m.Index, m.Mutation)
	}
}

func (s *Signer) sequenceOne(index, mutation []byte) {
	// Get current value.
	ctx := context.Background()
	v, err := s.tree.ReadLeaf(ctx, index)
	if err != nil {
		return
	}

	newV, err := s.mutator.Mutate(v, mutation)
	if err != nil {
		return
	}

	// Save new value and update tree.
	if err := s.tree.WriteLeaf(ctx, index, newV); err != nil {
		return
	}
}

// createEpoch watches the ticker channel and triggers epoch creation once the
// ticker ticks.
func (s *Signer) createEpoch() {
	for _ = range s.ticker.C {
		ctx := context.Background()
		timestamp := time.Now().Unix()
		root, err := s.tree.ReadRoot(ctx)
		if err != nil {
			log.Fatalf("Failed to create epoch: %v", err)
		}

		prevHash, err := s.sth.GetHLast(ctx)
		if err != nil {
			log.Fatalf("Failed to get previous epoch: %v", err)
		}
		headData, err := proto.Marshal(&ctmap.EpochHead{
			// TODO: set Realm
			IssueTime:    &tspb.Timestamp{timestamp, 0},
			PreviousHash: prevHash,
			Epoch:        timestamp,
			Root:         root,
		})
		if err != nil {
			log.Fatalf("Failed to marshal epoch: %v", err)
		}
		signedEpochHead, err := proto.Marshal(&ctmap.SignedEpochHead{
			EpochHead: headData,
			// TODO: set Signatures
		})
		if err != nil {
			log.Fatalf("Failed to marshal signed epoch: %v", err)
		}
		if err := s.sth.Append(ctx, signedEpochHead); err != nil {
			log.Fatalf("Failed to write SignedHead: %v", err)
		}
	}
}

// Stop stops the signer and release all associated resource.
func (s *Signer) Stop() {
	s.ticker.Stop()
}
