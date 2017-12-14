// Copyright 2017 Google Inc. All Rights Reserved.
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

package monitor

import (
	"context"
	"crypto"
	"fmt"
	"time"

	"github.com/google/keytransparency/core/client/mutationclient"
	"github.com/google/keytransparency/core/monitorstorage"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/merkle/hashers"

	"github.com/golang/glog"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tcrypto "github.com/google/trillian/crypto"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	mClient     pb.KeyTransparencyServiceClient
	signer      *tcrypto.Signer
	trusted     *trillian.SignedLogRoot
	mapID       int64
	logVerifier client.LogVerifier
	store       monitorstorage.Interface
	mapHasher   hashers.MapHasher
	mapPubKey   crypto.PublicKey
}

// NewFromConfig produces a new monitor from a Domain object.
func NewFromConfig(mclient pb.KeyTransparencyServiceClient,
	config *pb.Domain,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	logTree := config.GetLog()
	mapTree := config.GetMap()
	logHasher, err := hashers.NewLogHasher(logTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("could not initialize log hasher: %v", err)
	}
	logPubKey, err := der.UnmarshalPublicKey(logTree.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("failed parsing log public key: %v", err)
	}
	mapHasher, err := hashers.NewMapHasher(mapTree.GetHashStrategy())
	if err != nil {
		return nil, fmt.Errorf("failed creating map hasher: %v", err)
	}
	mapPubKey, err := der.UnmarshalPublicKey(mapTree.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal map public key: %v", err)
	}
	logVerifier := client.NewLogVerifier(logHasher, logPubKey)
	return New(mclient, logVerifier,
		mapTree.TreeId, mapHasher, mapPubKey,
		signer, store)
}

// New creates a new instance of the monitor.
func New(mclient pb.KeyTransparencyServiceClient,
	logVerifier client.LogVerifier,
	mapID int64, mapHasher hashers.MapHasher, mapPubKey crypto.PublicKey,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	return &Monitor{
		mClient:     mclient,
		logVerifier: logVerifier,
		mapID:       mapID,
		mapHasher:   mapHasher,
		mapPubKey:   mapPubKey,
		signer:      signer,
		store:       store,
	}, nil
}

// EpochPair is two adjacent epochs.
type EpochPair struct {
	EpochA, EpochB *pb.Epoch
}

// EpochPairs consumes epochs (0, 1, 2) and produces pairs (0,1), (1,2).
func EpochPairs(ctx context.Context, epochs <-chan *pb.Epoch, pairs chan<- EpochPair) error {
	var epochA *pb.Epoch
	for epoch := range epochs {
		if epochA == nil {
			epochA = epoch
			continue
		}
		pair := EpochPair{
			EpochA: epochA,
			EpochB: epoch,
		}
		select {
		case <-ctx.Done():
			close(pairs)
			return ctx.Err()
		case pairs <- pair:
		}
		epochA = epoch
	}
	return nil
}

// ProcessLoop continuously fetches mutations and processes them.
func (m *Monitor) ProcessLoop(ctx context.Context, domainID string, period time.Duration) error {
	mutCli := mutationclient.New(m.mClient, period)
	cctx, cancel := context.WithCancel(ctx)
	errc := make(chan error)
	epochs := make(chan *pb.Epoch)
	pairs := make(chan EpochPair)

	go func(ctx context.Context, domainID string, epochs chan<- *pb.Epoch) {
		errc <- mutCli.StreamEpochs(ctx, domainID, 0, epochs)
	}(cctx, domainID, epochs)
	go func(ctx context.Context, epochs <-chan *pb.Epoch, pairs chan<- EpochPair) {
		errc <- EpochPairs(ctx, epochs, pairs)
	}(cctx, epochs, pairs)
	defer cancel()

	for pair := range pairs {
		revision := pair.EpochB.GetSmr().GetMapRevision()
		mutations, err := mutCli.EpochMutations(ctx, pair.EpochB)
		if err != nil {
			return err
		}

		var smr *trillian.SignedMapRoot
		var errList []error
		if errs := m.VerifyEpochMutations(pair.EpochA, pair.EpochB, mutations); len(errs) > 0 {
			glog.Infof("Epoch %v did not verify: %v", revision, errs)
			errList = errs
		} else {
			// Sign if successful.
			smr, err = m.signMapRoot(pair.EpochB.GetSmr())
			if err != nil {
				return err
			}
		}

		// Save result.
		if err := m.store.Set(revision, &monitorstorage.Result{
			Smr:    smr,
			Seen:   time.Now(),
			Errors: errList,
		}); err != nil {
			return fmt.Errorf("monitorstorage.Set(%v, _): %v", revision, err)
		}
		return nil

	}
	errA := <-errc
	errB := <-errc
	if errA != nil || errB != nil {
		return fmt.Errorf("failed fetching epochs: (fetch: %v, pair: %v)", errA, errB)
	}
	return nil
}

// VerifyEpochMutations validates that epochA + mutations = epochB.
func (m *Monitor) VerifyEpochMutations(epochA, epochB *pb.Epoch, mutations []*pb.MutationProof) []error {
	revision := epochB.GetSmr().GetMapRevision()
	if errs := m.VerifyEpoch(epochB); len(errs) > 0 {
		glog.Errorf("Invalid Epoch %v: %v", revision, errs)
		return errs
	}

	// Fetch Previous root.
	SMRA := epochA.GetSmr()
	SMRB := epochB.GetSmr()
	if errs := m.verifyMutations(mutations, SMRA.GetRootHash(), SMRB.GetRootHash(), SMRB.GetMapId()); len(errs) > 0 {
		glog.Errorf("Invalid Epoch %v Mutations: %v", revision, errs)
		return errs
	}
	return nil

}
