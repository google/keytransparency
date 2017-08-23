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

package storage

import (
	"errors"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian"
)

var (
	ErrAlreadyStored = errors.New("already stored epoch")
	ErrNotFound      = errors.New("data for epoch not found")
)

type MonitoringResult struct {
	// in case of success this contains the map root signed by the monitor
	Smr *trillian.SignedMapRoot
	// response contains the original mutations API response from the server
	// in case at least one verification step failed
	Response *ktpb.GetMutationsResponse
	Seen     int64
	Errors   []error
}

type Storage struct {
	store map[int64]*MonitoringResult
	latest int64
}

func New() *Storage {
	return &Storage{
		store: make(map[int64]*MonitoringResult),
	}
}

func (s *Storage) Set(epoch int64,
	seenNanos int64,
	smr *trillian.SignedMapRoot,
	response *ktpb.GetMutationsResponse,
	errorList []error) error {
	// see if we already processed this epoch:
	if _, ok := s.store[epoch]; ok {
		return ErrAlreadyStored
	}
	// if not we just store the value:
	s.store[epoch] = &MonitoringResult{
		Smr:      smr,
		Seen:     seenNanos,
		Response: response,
		Errors:   errorList,
	}
	s.latest=epoch
	return nil
}

func (s *Storage) Get(epoch int64) (*MonitoringResult, error) {
	if result, ok := s.store[epoch]; ok {
		return result, nil
	}
	return nil, ErrNotFound
}

func (s *Storage) LatestEpoch() int64 {
	return s.latest
}
