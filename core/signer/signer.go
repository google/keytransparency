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
	"fmt"
	"log"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/queue"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/core/tree"

	"github.com/golang/protobuf/ptypes"
	"golang.org/x/net/context"

	"github.com/google/keytransparency/core/proto/ctmap"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	spb "github.com/google/keytransparency/core/proto/signature"
)

// Clock defines an interface for the advancement of time.
type Clock interface {
	Now() time.Time
}

// realClock returns the real time.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// fakeClock returns the same sequence of time each time.
type fakeClock int64

func (i fakeClock) Now() time.Time { i++; return time.Unix(int64(i), 0) }

// Signer processes mutations, applies them to the sparse merkle tree, and
// signes the sparse map head.
type Signer struct {
	realm     string
	queue     queue.Queuer
	mutator   mutator.Mutator
	tree      tree.Sparse
	mutations mutator.Mutation
	sths      appender.Appender
	signer    signatures.Signer
	clock     Clock
}

// New creates a new instance of the signer.
func New(realm string, queue queue.Queuer, tree tree.Sparse,
	mutator mutator.Mutator, sths appender.Appender, mutations mutator.Mutation,
	signer signatures.Signer) *Signer {
	return &Signer{
		realm:     realm,
		queue:     queue,
		mutator:   mutator,
		tree:      tree,
		sths:      sths,
		mutations: mutations,
		signer:    signer,
		clock:     realClock{},
	}
}

// FakeTime uses a clock that advances one second each time it is called for testing.
func (s *Signer) FakeTime() {
	s.clock = new(fakeClock)
}

// StartSigning inserts epoch advancement signals into the queue.
func (s *Signer) StartSigning(interval time.Duration) {
	for range time.NewTicker(interval).C {
		if err := s.queue.AdvanceEpoch(); err != nil {
			log.Fatalf("Advance epoch failed: %v", err)
		}
	}
}

// ProcessMutation saves a mutation and adds it to the append-only log and tree.
func (s *Signer) ProcessMutation(ctx context.Context, txn transaction.Txn, index, mutation []byte) error {
	epoch, err := s.tree.Epoch(txn)
	if err != nil {
		return fmt.Errorf("Epoch(): %v", err)
	}
	// Get current value.
	v, err := s.tree.ReadLeafAt(txn, index, epoch)
	if err != nil {
		return fmt.Errorf("ReadLeafAt err: %v", err)
	}

	newV, err := s.mutator.Mutate(v, mutation)
	if err != nil {
		return fmt.Errorf("Mutate err: %v", err)
	}

	// Save new value and update tree.
	if err := s.tree.QueueLeaf(txn, index, newV); err != nil {
		return fmt.Errorf("QueueLeaf err: %v", err)
	}

	mutationObj := new(tpb.SignedKV)
	if err := proto.Unmarshal(mutation, mutationObj); err != nil {
		return err
	}
	if _, err := s.mutations.Write(txn, mutationObj); err != nil {
		return fmt.Errorf("Mutation write failed: %v", err)
	}

	log.Printf("Sequenced %x", index)
	return nil
}

// CreateEpoch signs the current map head.
func (s *Signer) CreateEpoch(ctx context.Context, txn transaction.Txn) error {
	if err := s.tree.Commit(txn); err != nil {
		return fmt.Errorf("Commit(): %v", err)
	}
	epoch, err := s.tree.Epoch(txn)
	if err != nil {
		return fmt.Errorf("Epoch(): %v", err)
	}
	root, err := s.tree.ReadRootAt(txn, epoch)
	if err != nil {
		return fmt.Errorf("ReadRootAt(%v): %v", epoch, err)
	}
	timestamp, err := ptypes.TimestampProto(s.clock.Now())
	if err != nil {
		return err
	}

	mh := &ctmap.MapHead{
		Realm:     s.realm,
		IssueTime: timestamp,
		Epoch:     epoch,
		Root:      root,
	}
	sig, err := s.signer.Sign(mh)
	if err != nil {
		return err
	}
	smh := &ctmap.SignedMapHead{
		MapHead:    mh,
		Signatures: map[string]*spb.DigitallySigned{s.signer.KeyID(): sig},
	}
	if err := s.sths.Append(ctx, txn, epoch, smh); err != nil {
		return fmt.Errorf("Append SMH failure %v", err)
	}
	log.Printf("Created epoch %v. SMH: %#x", epoch, root)
	return nil
}
