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

// Package sequencerservice contains the implementation of the sequencer service
// defined in core/impl/proto/sequencer_v1_service.
package sequencerservice

import (
	"github.com/golang/glog"
	"github.com/google/keytransparency/core/sequencer"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	spb "github.com/google/keytransparency/impl/proto/sequencer_v1_service"
)

// Server implements the sequencer service server.
type Server struct {
	seq *sequencer.Sequencer
}

// New creates a new instance of a sequencer service server.
func New(seq *sequencer.Sequencer) *Server {
	return &Server{
		seq: seq,
	}
}

// GetEpochs is a streaming API that sends epoch mutations upon creation.
func (s *Server) GetEpochs(in *tpb.GetEpochsRequest, stream spb.SequencerService_GetEpochsServer) error {
	ch := make(chan *tpb.GetMutationsResponse, 1)
	s.seq.RegisterMutationsChannel(ch)
	go listen(ch, stream)
	return nil
}

func listen(ch chan *tpb.GetMutationsResponse, stream spb.SequencerService_GetEpochsServer) {
	for mutations := range ch {
		resp := &tpb.GetEpochsResponse{
			Mutations: mutations,
		}
		if err := stream.Send(resp); err != nil {
			glog.Errorf("SequencerService_GetEpochsServer.Send(%v) failed: %v", resp, err)
		}
	}
}
