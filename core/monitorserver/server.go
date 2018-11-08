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

// Package monitor implements the monitor service. A monitor repeatedly polls a
// key-transparency server's Mutations API and signs Map Roots if it could
// reconstruct
// clients can query.

// Package monitorserver contains an implementation of a Monitor server which can be
// queried for monitoring results.
package monitorserver

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/monitor"
	"github.com/google/keytransparency/core/monitorstorage"

	pb "github.com/google/keytransparency/core/api/monitor/v1/monitor_go_proto"
)

var (
	// ErrNothingProcessed occurs when the monitor did not process any mutations /
	// smrs yet.
	ErrNothingProcessed = errors.New("did not process any mutations yet")
)

// Server holds internal state for the monitor server. It serves monitoring
// responses via a grpc and HTTP API.
type Server struct {
	storage monitorstorage.Interface
}

// New creates a new instance of the monitor server.
func New(storage monitorstorage.Interface) *Server {
	return &Server{
		storage: storage,
	}
}

// GetState returns the latest valid signed map root the monitor
// observed. Additionally, the response contains additional data necessary to
// reproduce errors on failure.
//
// Returns the signed map root for the latest revision the monitor observed. If
// the monitor could not reconstruct the map root given the set of mutations
// from the previous to the current revision it won't sign the map root and
// additional data will be provided to reproduce the failure.
func (s *Server) GetState(ctx context.Context, in *pb.GetStateRequest) (*pb.State, error) {
	latestRevision := s.storage.LatestRevision()
	if latestRevision == 0 {
		return nil, ErrNothingProcessed
	}
	return s.getResponseByRevision(latestRevision)
}

// GetStateByRevision works similar to GetSignedMapRoot but returns
// the monitor's result for a specific map revision.
//
// Returns the signed map root for the specified revision the monitor observed.
// If the monitor could not reconstruct the map root given the set of
// mutations from the previous to the current revision it won't sign the map root
// and additional data will be provided to reproduce the failure.
func (s *Server) GetStateByRevision(ctx context.Context, in *pb.GetStateRequest) (*pb.State, error) {
	return s.getResponseByRevision(in.GetRevision())
}

func (s *Server) getResponseByRevision(revision int64) (*pb.State, error) {
	r, err := s.storage.Get(revision)
	if err == monitorstorage.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "Could not find monitoring response for revision %d", revision)
	}

	errs := monitor.ErrList(r.Errors)
	seen, err := ptypes.TimestampProto(r.Seen)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "invalid timestamp: %v", err)
	}
	// Convert errors into rpc.Status
	return &pb.State{
		Smr:      r.Smr,
		SeenTime: seen,
		Errors:   errs.Proto(),
	}, nil
}
