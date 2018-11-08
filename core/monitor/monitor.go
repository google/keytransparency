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

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/monitorstorage"

	"github.com/google/trillian"
	"github.com/google/trillian/types"

	"github.com/golang/glog"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
	tcrypto "github.com/google/trillian/crypto"
)

// Monitor holds the internal state for a monitor accessing the mutations API
// and for verifying its responses.
type Monitor struct {
	cli         *client.Client
	logVerifier *tclient.LogVerifier
	mapVerifier *tclient.MapVerifier
	signer      *tcrypto.Signer
	store       monitorstorage.Interface
}

// NewFromDirectory produces a new monitor from a Directory object.
func NewFromDirectory(cli pb.KeyTransparencyClient,
	config *pb.Directory,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	logVerifier, err := tclient.NewLogVerifierFromTree(config.GetLog())
	if err != nil {
		return nil, fmt.Errorf("could not initialize log verifier: %v", err)
	}
	mapVerifier, err := tclient.NewMapVerifierFromTree(config.GetMap())
	if err != nil {
		return nil, fmt.Errorf("could not initialize map verifier: %v", err)
	}

	ktClient, err := client.NewFromConfig(cli, config)
	if err != nil {
		return nil, fmt.Errorf("could not create kt client: %v", err)
	}

	return New(ktClient, logVerifier, mapVerifier, signer, store)
}

// New creates a new instance of the monitor.
func New(cli *client.Client,
	logVerifier *tclient.LogVerifier,
	mapVerifier *tclient.MapVerifier,
	signer *tcrypto.Signer,
	store monitorstorage.Interface) (*Monitor, error) {
	return &Monitor{
		cli:         cli,
		logVerifier: logVerifier,
		mapVerifier: mapVerifier,
		signer:      signer,
		store:       store,
	}, nil
}

// RevisionPair is two adjacent revisions.
type RevisionPair struct {
	A, B *pb.Revision
}

// RevisionPairs consumes revisions (0, 1, 2) and produces pairs (0,1), (1,2).
func RevisionPairs(ctx context.Context, revisions <-chan *pb.Revision, pairs chan<- RevisionPair) error {
	defer close(pairs)
	var revisionA *pb.Revision
	for revision := range revisions {
		if revisionA == nil {
			revisionA = revision
			continue
		}
		pair := RevisionPair{
			A: revisionA,
			B: revision,
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case pairs <- pair:
		}
		revisionA = revision
	}
	return nil
}

// ProcessLoop continuously fetches mutations and processes them.
func (m *Monitor) ProcessLoop(ctx context.Context, directoryID string, trusted types.LogRootV1) error {
	cctx, cancel := context.WithCancel(ctx)
	errc := make(chan error)
	revisions := make(chan *pb.Revision)
	pairs := make(chan RevisionPair)

	go func(ctx context.Context) {
		err := m.cli.StreamRevisions(ctx, directoryID, int64(trusted.TreeSize), revisions)
		glog.Errorf("StreamRevisions(%v): %v", directoryID, err)
		errc <- err
	}(cctx)
	go func(ctx context.Context) {
		err := RevisionPairs(ctx, revisions, pairs)
		glog.Errorf("RevisionPairs(): %v", err)
		errc <- err
	}(cctx)
	defer cancel()

	for pair := range pairs {
		_, mapRootB, err := m.cli.VerifyRevision(pair.B, trusted)
		if err != nil {
			glog.Errorf("Invalid Revision %v: %v", mapRootB.Revision, err)
			return err
		}

		mutations, err := m.cli.RevisionMutations(ctx, pair.B)
		if err != nil {
			return err
		}

		var smr *trillian.SignedMapRoot
		var errList []error

		if errs := m.verifyMutations(mutations, pair.A.GetMapRoot().GetMapRoot(), mapRootB); len(errs) > 0 {
			glog.Errorf("Invalid Revision %v Mutations: %v", mapRootB.Revision, errs)
			errList = errs
		} else {
			// Sign if successful.
			smr, err = m.signer.SignMapRoot(mapRootB)
			if err != nil {
				return err
			}
		}

		// Save result.
		if err := m.store.Set(int64(mapRootB.Revision), &monitorstorage.Result{
			Smr:    smr,
			Seen:   time.Now(),
			Errors: errList,
		}); err != nil {
			return fmt.Errorf("monitorstorage.Set(%v, _): %v", mapRootB.Revision, err)
		}
	}
	errA := <-errc
	errB := <-errc
	if err := errA; err != nil {
		return err
	}
	return errB
}
