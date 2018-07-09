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

	"github.com/google/keytransparency/core/domain"
	"github.com/google/keytransparency/core/mutator"
	"google.golang.org/grpc"

	"github.com/golang/glog"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
	tclient "github.com/google/trillian/client"
)

// Sequencer processes mutations and sends them to the trillian map.
type Sequencer struct {
	domains         domain.Storage
	tlog            tpb.TrillianLogClient
	mapAdmin        tpb.TrillianAdminClient
	tmap            tpb.TrillianMapClient
	queue           mutator.MutationQueue
	receivers       map[string]mutator.Receiver
	batchSize       int32
	sequencerClient spb.KeyTransparencySequencerClient
}

// New creates a new instance of the signer.
func New(
	sequencerClient spb.KeyTransparencySequencerClient,
	tlog tpb.TrillianLogClient,
	tmap tpb.TrillianMapClient,
	mapAdmin tpb.TrillianAdminClient,
	domains domain.Storage,
	mutations mutator.MutationStorage,
	queue mutator.MutationQueue,
	batchSize int,
) *Sequencer {
	return &Sequencer{
		sequencerClient: sequencerClient,
		domains:         domains,
		tlog:            tlog,
		tmap:            tmap,
		mapAdmin:        mapAdmin,
		queue:           queue,
		receivers:       make(map[string]mutator.Receiver),
		batchSize:       int32(batchSize),
	}
}

// RunAndConnect creates a local gRPC server returns a connected client.
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
		conn.Close()
		server.Stop()
		lis.Close()
	}

	client = spb.NewKeyTransparencySequencerClient(conn)
	return client, stop, err
}

// Close stops all receivers and releases resources.
func (s *Sequencer) Close() {
	for _, r := range s.receivers {
		r.Close()
	}
}

// ListenForNewDomains starts receivers for all domains and periodically checks for new domains.
func (s *Sequencer) ListenForNewDomains(ctx context.Context, refresh time.Duration) error {
	ticker := time.NewTicker(refresh)
	defer func() { ticker.Stop() }()

	for {
		select {
		case <-ticker.C:
			domains, err := s.domains.List(ctx, false)
			if err != nil {
				return fmt.Errorf("admin.List(): %v", err)
			}
			for _, d := range domains {
				knownDomains.Set(1, d.DomainID)
				if _, ok := s.receivers[d.DomainID]; !ok {
					glog.Infof("StartSigning domain: %v", d.DomainID)
					r, err := s.NewReceiver(ctx, d)
					if err != nil {
						return err
					}
					s.receivers[d.DomainID] = r
				}
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// NewReceiver creates a new receiver for a domain.
// New epochs will be created at least once per maxInterval and as often as minInterval.
func (s *Sequencer) NewReceiver(ctx context.Context, d *domain.Domain) (mutator.Receiver, error) {
	cctx, cancel := context.WithTimeout(ctx, d.MinInterval)
	defer cancel()
	mapTree, err := s.mapAdmin.GetTree(cctx, &tpb.GetTreeRequest{TreeId: d.MapID})
	if err != nil {
		return nil, err
	}
	mapVerifier, err := tclient.NewMapVerifierFromTree(mapTree)
	if err != nil {
		return nil, err
	}

	rootResp, err := s.tmap.GetSignedMapRoot(cctx, &tpb.GetSignedMapRootRequest{MapId: d.MapID})
	if err != nil {
		return nil, err
	}
	cancel()
	// Fetch last time from previous map head (as stored in the map server)
	mapRoot, err := mapVerifier.VerifySignedMapRoot(rootResp.GetMapRoot())
	if err != nil {
		return nil, err
	}
	last := time.Unix(0, int64(mapRoot.TimestampNanos))

	return s.queue.NewReceiver(ctx, last, d.DomainID, func(mutations []*mutator.QueueMessage) error {
		msgs := make([]*ktpb.EntryUpdate, 0, len(mutations))
		for _, m := range mutations {
			msgs = append(msgs, &ktpb.EntryUpdate{
				Mutation:  m.Mutation,
				Committed: m.ExtraData,
			})
		}
		_, err := s.sequencerClient.CreateEpoch(ctx, &spb.CreateEpochRequest{
			DomainId: d.DomainID,
			Messages: msgs,
		})
		return err
	}, mutator.ReceiverOptions{
		MaxBatchSize: s.batchSize,
		Period:       d.MinInterval,
		MaxPeriod:    d.MaxInterval,
	}), nil
}
