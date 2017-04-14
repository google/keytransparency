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
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/keytransparency/core/tree"

	"github.com/golang/protobuf/ptypes"
	"golang.org/x/net/context"

	"github.com/google/keytransparency/core/proto/ctmap"
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
	mutator   mutator.Mutator
	tree      tree.Sparse
	mutations mutator.Mutation
	sths      appender.Appender
	signer    signatures.Signer
	factory   transaction.Factory
	clock     Clock
}

// New creates a new instance of the signer.
func New(realm string, tree tree.Sparse,
	mutator mutator.Mutator, sths appender.Appender, mutations mutator.Mutation,
	signer signatures.Signer, factory transaction.Factory) *Signer {
	return &Signer{
		realm:     realm,
		mutator:   mutator,
		tree:      tree,
		sths:      sths,
		mutations: mutations,
		signer:    signer,
		factory:   factory,
		clock:     realClock{},
	}
}

// FakeTime uses a clock that advances one second each time it is called for testing.
func (s *Signer) FakeTime() {
	s.clock = new(fakeClock)
}

// StartSigning advance epochs once per interval.
func (s *Signer) StartSigning(ctx context.Context, interval time.Duration) {
	for range time.NewTicker(interval).C {
		if err := s.CreateEpoch(ctx); err != nil {
			log.Fatalf("CreateEpoch failed: %v", err)
		}
	}
}

// queueMutation saves a mutation and adds it to the tree.
func (s *Signer) queueMutation(txn transaction.Txn, index, mutation []byte) error {
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

	log.Printf("Sequenced %x", index)
	return nil
}

// processMutations reads mutations from the database and adds them to the tree.
// processMutations returns the maximum mutation sequence number processed.
func (s *Signer) processMutations(ctx context.Context, txn transaction.Txn) (uint64, error) {
	startSequence := uint64(0)
	smh := new(ctmap.SignedMapHead)
	if _, _, err := s.sths.Latest(ctx, smh); err == nil {
		startSequence = smh.GetMapHead().MaxSequenceNumber + 1
	} else if err != sql.ErrNoRows {
		return 0, fmt.Errorf("Latest err: %v", err)
	}
	maxSequence, mutations, err := s.mutations.ReadAll(txn, startSequence)
	if err != nil {
		return 0, fmt.Errorf("ReadRange err: %v", err)
	}
	for _, mutation := range mutations {
		mData, err := proto.Marshal(mutation)
		if err != nil {
			return 0, err
		}
		if err := s.queueMutation(txn, mutation.GetKeyValue().Key, mData); err != nil {
			return 0, fmt.Errorf("queueMutation err: %v", err)
		}
	}
	return maxSequence, nil
}

// CreateEpoch signs the current map head.
func (s *Signer) CreateEpoch(ctx context.Context) error {
	txn, err := s.factory.NewDBTxn(ctx)
	if err != nil {
		return fmt.Errorf("NewDBTxn() failed: %v", err)
	}
	if err := s.createEpoch(ctx, txn); err != nil {
		if err := txn.Rollback(); err != nil {
			log.Printf("Cannot rollback the transaction: %v", err)
		}
		return fmt.Errorf("createEpoch() failed: %v", err)
	}
	if err := txn.Commit(); err != nil {
		return fmt.Errorf("txn.Commit() failed: %v", err)
	}
	return nil
}

func (s *Signer) createEpoch(ctx context.Context, txn transaction.Txn) error {
	maxSequence, err := s.processMutations(ctx, txn)
	if err != nil {
		return fmt.Errorf("processMutations err: %v", err)
	}
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
		Realm:             s.realm,
		IssueTime:         timestamp,
		Epoch:             epoch,
		Root:              root,
		MaxSequenceNumber: maxSequence,
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
