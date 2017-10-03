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

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1"
	"github.com/google/trillian"
)

var (
	// ErrAlreadyStored is raised if the caller tries storing a response which
	// has already been stored.
	ErrAlreadyStored = errors.New("already stored epoch")
	// ErrNotFound is raised if the caller tries to retrieve data for an epoch
	// which has not been processed and stored yet.
	ErrNotFound = errors.New("data for epoch not found")
)

// MonitoringResult stores all data
type MonitoringResult struct {
	// Smr contains the map root signed by the monitor in case all verifications
	// have passed.
	Smr *trillian.SignedMapRoot
	// Seen is the unix timestamp at which the mutations response has been
	// received.
	Seen int64
	// Errors contains a string representation of the verifications steps that
	// failed.
	Errors []error
	// Response contains the original mutations API response from the server
	// in case at least one verification step failed.
	Response *pb.GetMutationsResponse
}

// Storage is an in-memory store for the monitoring results.
type Storage struct {
	store  map[int64]*MonitoringResult
	latest int64
}

// New initializes a
func New() *Storage {
	return &Storage{
		store: make(map[int64]*MonitoringResult),
	}
}

// Set internally stores the given data as a MonitoringResult which can be
// retrieved by Get.
func (s *Storage) Set(epoch int64,
	seenNanos int64,
	smr *trillian.SignedMapRoot,
	response *pb.GetMutationsResponse,
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
	s.latest = epoch
	return nil
}

// Get returns the MonitoringResult for the given epoch. It returns an error
// if the result does not exist.
func (s *Storage) Get(epoch int64) (*MonitoringResult, error) {
	if result, ok := s.store[epoch]; ok {
		return result, nil
	}
	return nil, ErrNotFound
}

// LatestEpoch is a convenience method to retrieve the latest stored epoch.
func (s *Storage) LatestEpoch() int64 {
	return s.latest
}
