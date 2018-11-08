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
	"net"
	"time"

	"github.com/golang/glog"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/directory"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// Sequencer processes mutations and sends them to the trillian map.
type Sequencer struct {
	directories     directory.Storage
	mapAdmin        tpb.TrillianAdminClient
	batchSize       int32
	sequencerClient spb.KeyTransparencySequencerClient
}

// New creates a new instance of the signer.
func New(
	sequencerClient spb.KeyTransparencySequencerClient,
	mapAdmin tpb.TrillianAdminClient,
	directories directory.Storage,
	batchSize int32,
) *Sequencer {
	return &Sequencer{
		sequencerClient: sequencerClient,
		directories:     directories,
		mapAdmin:        mapAdmin,
		batchSize:       batchSize,
	}
}

// RunAndConnect creates a local gRPC server and returns a connected client.
func RunAndConnect(ctx context.Context, impl spb.KeyTransparencySequencerServer) (client spb.KeyTransparencySequencerClient, stop func(), startErr error) {
	server := grpc.NewServer()
	spb.RegisterKeyTransparencySequencerServer(server, impl)

	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, func() {}, fmt.Errorf("error creating TCP listener: %v", err)
	}
	defer func() {
		if startErr != nil {
			lis.Close()
		}
	}()

	go func() {
		if err := server.Serve(lis); err != nil {
			glog.Errorf("server exited with error: %v", err)
		}
	}()

	addr := lis.Addr().String()
	conn, err := grpc.DialContext(ctx, addr, grpc.WithInsecure())
	if err != nil {
		return nil, func() {}, fmt.Errorf("error connecting to %v: %v", addr, err)
	}

	stop = func() {
		server.GracefulStop()
		conn.Close()
		lis.Close()
	}

	client = spb.NewKeyTransparencySequencerClient(conn)
	return client, stop, err
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

// RunBatchForAllDirectories scans the directories table for new directories and creates new receivers for
// directories that the sequencer is not currently receiving for.
func (s *Sequencer) RunBatchForAllDirectories(ctx context.Context) error {
	directories, err := s.directories.List(ctx, false)
	if err != nil {
		return fmt.Errorf("admin.List(): %v", err)
	}
	for _, d := range directories {
		knownDirectories.Set(1, d.DirectoryID)
		req := &spb.RunBatchRequest{
			DirectoryId: d.DirectoryID,
			MinBatch:    1,
			MaxBatch:    s.batchSize,
		}
		if _, err := s.sequencerClient.RunBatch(ctx, req); err != nil {
			return err
		}
	}
	return nil
}
