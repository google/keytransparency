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

package fake

import (
	"github.com/google/trillian"

	"github.com/google/keytransparency/core/monitorstorage"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

// MonitorStorage is an in-memory store for the monitoring results.
type MonitorStorage struct {
	store  map[int64]*monitorstorage.Result
	latest int64
}

// NewMonitorStorage returns an in-memory place store monitoring results.
func NewMonitorStorage() *MonitorStorage {
	return &MonitorStorage{
		store: make(map[int64]*monitorstorage.Result),
	}
}

// Set internally stores the given data as a MonitoringResult which can be
// retrieved by Get.
func (s *MonitorStorage) Set(epoch int64,
	seenNanos int64,
	smr *trillian.SignedMapRoot,
	response *pb.GetMutationsResponse,
	errorList []error) error {
	// see if we already processed this epoch:
	if _, ok := s.store[epoch]; ok {
		return monitorstorage.ErrAlreadyStored
	}
	// if not we just store the value:
	s.store[epoch] = &monitorstorage.Result{
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
func (s *MonitorStorage) Get(epoch int64) (*monitorstorage.Result, error) {
	if result, ok := s.store[epoch]; ok {
		return result, nil
	}
	return nil, monitorstorage.ErrNotFound
}

// LatestEpoch is a convenience method to retrieve the latest stored epoch.
func (s *MonitorStorage) LatestEpoch() int64 {
	return s.latest
}
