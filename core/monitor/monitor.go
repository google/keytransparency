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
	"fmt"
	"time"

	"github.com/google/keytransparency/core/client/mutationclient"
	"github.com/google/keytransparency/core/monitorstorage"

	"github.com/google/trillian"
	"github.com/google/trillian/client"

	"github.com/golang/glog"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	tcrypto "github.com/google/trillian/crypto"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	mClient     pb.KeyTransparencyClient
	signer      *tcrypto.Signer
	trusted     trillian.SignedLogRoot
	logVerifier client.LogVerifier
	mapVerifier *client.MapVerifier
	store       monitorstorage.Interface
}

// NewFromDomain produces a new monitor from a Domain object.
func NewFromDomain(mClient pb.KeyTransparencyClient,
	config *pb.Domain,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	logVerifier, err := client.NewLogVerifierFromTree(config.GetLog())
	if err != nil {
		return nil, fmt.Errorf("could not initialize log verifier: %v", err)
	}
	mapVerifier, err := client.NewMapVerifierFromTree(config.GetMap())
	if err != nil {
		return nil, fmt.Errorf("could not initialize map verifier: %v", err)
	}
	return New(mClient, logVerifier, mapVerifier, signer, store)
}

// New creates a new instance of the monitor.
func New(mClient pb.KeyTransparencyClient,
	logVerifier client.LogVerifier,
	mapVerifier *client.MapVerifier,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	return &Monitor{
		mClient:     mClient,
		logVerifier: logVerifier,
		mapVerifier: mapVerifier,
		signer:      signer,
		store:       store,
	}, nil
}

// EpochPair is two adjacent epochs.
type EpochPair struct {
	A, B *pb.Epoch
}

// EpochPairs consumes epochs (0, 1, 2) and produces pairs (0,1), (1,2).
func EpochPairs(ctx context.Context, epochs <-chan *pb.Epoch, pairs chan<- EpochPair) error {
	defer close(pairs)
	var epochA *pb.Epoch
	for epoch := range epochs {
		if epochA == nil {
			epochA = epoch
			continue
		}
		pair := EpochPair{
			A: epochA,
			B: epoch,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pairs <- pair:
		}
		epochA = epoch
	}
	return nil
}

// ProcessLoop continuously fetches mutations and processes them.
func (m *Monitor) ProcessLoop(ctx context.Context, domainID string, trusted trillian.SignedLogRoot, period time.Duration) error {
	mutCli := mutationclient.New(m.mClient, period)
	cctx, cancel := context.WithCancel(ctx)
	errc := make(chan error)
	epochs := make(chan *pb.Epoch)
	pairs := make(chan EpochPair)

	go func(ctx context.Context) {
		errc <- mutCli.StreamEpochs(ctx, domainID, trusted.TreeSize, epochs)
	}(cctx)
	go func(ctx context.Context) {
		errc <- EpochPairs(ctx, epochs, pairs)
	}(cctx)
	defer cancel()

	for pair := range pairs {
		revision := pair.B.GetSmr().GetMapRevision()
		mutations, err := mutCli.EpochMutations(ctx, pair.B)
		if err != nil {
			return err
		}

		var smr *trillian.SignedMapRoot
		var errList []error
		if errs := m.VerifyEpochMutations(pair.A, pair.B, &trusted, mutations); len(errs) > 0 {
			glog.Infof("Epoch %v did not verify: %v", revision, errs)
			errList = errs
		} else {
			// Sign if successful.
			smr, err = m.signMapRoot(pair.B.GetSmr())
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
	}
	errA := <-errc
	errB := <-errc
	if err := errA; err != nil {
		return err
	}
	return errB
}

// VerifyEpochMutations validates that epochA + mutations = epochB.
func (m *Monitor) VerifyEpochMutations(epochA, epochB *pb.Epoch, trusted *trillian.SignedLogRoot, mutations []*pb.MutationProof) []error {
	revision := epochB.GetSmr().GetMapRevision()
	if errs := m.VerifyEpoch(epochB, trusted); len(errs) > 0 {
		glog.Errorf("Invalid Epoch %v: %v", revision, errs)
		return errs
	}

	// Fetch Previous root.
	if errs := m.verifyMutations(mutations, epochA.GetSmr(), epochB.GetSmr()); len(errs) > 0 {
		glog.Errorf("Invalid Epoch %v Mutations: %v", revision, errs)
		return errs
	}
	return nil

}
