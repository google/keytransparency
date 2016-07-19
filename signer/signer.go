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

	"github.com/google/key-transparency/appender"
	"github.com/google/key-transparency/mutator"
	"github.com/google/key-transparency/queue"
	"github.com/google/key-transparency/signatures"
	"github.com/google/key-transparency/tree"

	"github.com/golang/protobuf/proto"
	"golang.org/x/net/context"

	ctmap "github.com/google/key-transparency/proto/security_ctmap"
	tspb "github.com/google/key-transparency/proto/security_protobuf"
)

// Signer processes mutations, applies them to the sparse merkle tree, and
// signes the sparse map head.
type Signer struct {
	realm     string
	queue     queue.Queuer
	mutator   mutator.Mutator
	tree      tree.SparseHist
	mutations appender.Appender
	sths      appender.Appender
	signer    *signatures.SignatureSigner
}

// New creates a new instance of the signer.
func New(realm string, queue queue.Queuer, tree tree.SparseHist, mutator mutator.Mutator,
	sths, mutations appender.Appender, signer *signatures.SignatureSigner) *Signer {
	return &Signer{
		realm:     realm,
		queue:     queue,
		mutator:   mutator,
		tree:      tree,
		sths:      sths,
		mutations: mutations,
		signer:    signer,
	}
}

// StartSigning inserts epoch advancement signals into the queue.
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
	// Send mutation to append-only log.
	ctx := context.Background()
	s.mutations.Append(ctx, 0, mutation)

	// Get current value.
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

// CreateEpoch signs the current map head.
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

	mh := &ctmap.MapHead{
		Realm:     s.realm,
		IssueTime: &tspb.Timestamp{timestamp, 0},
		Epoch:     epoch,
		Root:      root,
	}
	sig, err := s.signer.Sign(mh)
	if err != nil {
		return err
	}
	smh := &ctmap.SignedMapHead{
		MapHead:    mh,
		Signatures: map[string]*ctmap.DigitallySigned{s.signer.KeyName: sig},
	}
	signedMapHead, err := proto.Marshal(smh)
	if err != nil {
		return err
	}
	if err := s.sths.Append(ctx, epoch, signedMapHead); err != nil {
		log.Printf("Append failure %v", err)
		return err
	}
	log.Printf("Created epoch %v. STH: %#x", epoch, root)
	return nil
}
