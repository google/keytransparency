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

// Package mapserver implements a verifiable map
package mapserver

import (
	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/db/queue"
	"github.com/google/e2e-key-server/tree"

	"golang.org/x/net/context"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
)

// Server holds internal state for the map server.
type Server struct {
	queue    queue.Queuer
	tree     tree.SparseHist
	appender appender.Appender
}

func New(queue queue.Queuer, tree tree.SparseHist, appender appender.Appender) *Server {
	return &Server{
		queue:    queue,
		tree:     tree,
		appender: appender,
	}
}

func (s *Server) Get(ctx context.Context, in *ctmap.GetRequest) (*ctmap.GetResponse, error) {
	// Inclusion proof
	neighbors, err := s.tree.NeighborsAt(ctx, index, e)
	if err != nil {
		return nil, err
	}

	// Get the data
	leaf, err := s.tree.ReadLeafAt(ctx, index, e)
	// Asence proof: data will be nil

	return &ctmap.GetResponse{
		neighbors: neighbors,
		leaf:      leaf,
	}
}

func (s *Server) Consistency(ctx context.Context, in *ctmap.GetRequest) (*ctmap.GetResponse, error) {
	// If end epoch is missing, replace with latest STH.
	e := in.end
	if in.Epoch == 0 {
		e = s.appender.Latest(ctx)
	}

	data, err := s.appender.GetByIndex(ctx, e)
	if err != nil {
		return nil, err
	}

	seh := ctmap.SignedEpochHead{}
	err = proto.Unmarshal(data, &seh)
	if err != nil {
		return nil, err
	}

}
