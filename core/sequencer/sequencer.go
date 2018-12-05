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

// Package sequencer reads mutations and applies them to the Trillian Map.
package sequencer

import (
	"context"
	"fmt"
	"time"

	"github.com/golang/glog"

	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/core/sequencer/election"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// Sequencer processes mutations and sends them to the trillian map.
type Sequencer struct {
	directories     directory.Storage
	mapAdmin        tpb.TrillianAdminClient
	batchSize       int32
	sequencerClient spb.KeyTransparencySequencerClient
	tracker         *election.Tracker
}

// New creates a new instance of the signer.
func New(
	sequencerClient spb.KeyTransparencySequencerClient,
	mapAdmin tpb.TrillianAdminClient,
	directories directory.Storage,
	batchSize int32,
	tracker *election.Tracker,
) *Sequencer {
	return &Sequencer{
		sequencerClient: sequencerClient,
		directories:     directories,
		mapAdmin:        mapAdmin,
		batchSize:       batchSize,
		tracker:         tracker,
	}
}

// PeriodicallyRun executes f once per tick until ctx is closed.
// Closing ctx will also stop any in-flight operation mid-way through.
func PeriodicallyRun(ctx context.Context, tickch <-chan time.Time, f func(ctx context.Context)) {
	if f == nil {
		glog.Errorf("cannot schedule nil function")
		return
	}
	for range tickch {
		select {
		case <-ctx.Done():
			return
		default:
		}
		// Give each invocation of f a separate context.
		// Prevent f from creating detached go routines using ctx.
		cctx, cancel := context.WithCancel(ctx)
		f(cctx)
		cancel()
	}
}

// TrackMasterships monitors resources for mastership.
func (s *Sequencer) TrackMasterships(ctx context.Context) {
	s.tracker.Run(ctx)
}

// RunBatchForAllDirectories scans the directories table for new directories and creates new receivers for
// directories that the sequencer is not currently receiving for.
func (s *Sequencer) RunBatchForAllDirectories(ctx context.Context) error {
	directories, err := s.directories.List(ctx, false)
	if err != nil {
		return fmt.Errorf("admin.List(): %v", err)
	}
	for _, d := range directories {
		knownDirectories.Set(1, d.DirectoryID)
		s.tracker.AddResource(d.DirectoryID)
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()
	masterships, err := s.tracker.Masterships(cctx)
	if err != nil {
		return err
	}

	var lastErr error
	for dirID, whileMaster := range masterships {
		req := &spb.RunBatchRequest{
			DirectoryId: dirID,
			MinBatch:    1,
			MaxBatch:    s.batchSize,
		}
		if _, err := s.sequencerClient.RunBatch(whileMaster, req); err != nil {
			lastErr = err
			glog.Errorf("RunBatch for %v failed: %v", dirID, err)
			return err
		}
	}

	return lastErr
}
