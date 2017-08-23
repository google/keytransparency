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

// Package monitor contains an implementation of a Monitor server which can be
// queried for monitoring results.
package monitor

import (
	"errors"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"github.com/google/keytransparency/core/monitor/storage"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_types"
)

var (
	// ErrNothingProcessed occurs when the monitor did not process any mutations /
	// smrs yet.
	ErrNothingProcessed = errors.New("did not process any mutations yet")
)

// Server holds internal state for the monitor server. It serves monitoring
// responses via a grpc and HTTP API.
type Server struct {
	storage *storage.Storage
}

// New creates a new instance of the monitor server.
func New(storage *storage.Storage) *Server {
	return &Server{
		storage: storage,
	}
}

// GetSignedMapRoot returns the latest valid signed map root the monitor
// observed. Additionally, the response contains additional data necessary to
// reproduce errors on failure.
//
// Returns the signed map root for the latest epoch the monitor observed. If
// the monitor could not reconstruct the map root given the set of mutations
// from the previous to the current epoch it won't sign the map root and
// additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRoot(ctx context.Context, in *mopb.GetMonitoringRequest) (*mopb.GetMonitoringResponse, error) {
	latestEpoch := s.storage.LatestEpoch()
	return s.getResponseByRevision(latestEpoch)
}

// GetSignedMapRootByRevision works similar to GetSignedMapRoot but returns
// the monitor's result for a specific map revision.
//
// Returns the signed map root for the specified epoch the monitor observed.
// If the monitor could not reconstruct the map root given the set of
// mutations from the previous to the current epoch it won't sign the map root
// and additional data will be provided to reproduce the failure.
func (s *Server) GetSignedMapRootByRevision(ctx context.Context, in *mopb.GetMonitoringRequest) (*mopb.GetMonitoringResponse, error) {
	return s.getResponseByRevision(in.GetEpoch())
}

func (s *Server) getResponseByRevision(epoch int64) (*mopb.GetMonitoringResponse, error) {
	res, err := s.storage.Get(epoch)
	if err == storage.ErrNotFound {
		return nil, grpc.Errorf(codes.NotFound,
			"Could not find monitoring response for epoch %d", epoch)
	}

	resp := &mopb.GetMonitoringResponse{
		Smr:                res.Smr,
		SeenTimestampNanos: res.Seen,
	}

	if len(res.Errors) > 0 {
		for _, err := range res.Errors {
			resp.Errors = append(resp.Errors, err.Error())
		}
		// data to replay the verification steps:
		resp.ErrorData = res.Response
	}

	return resp, nil
}
