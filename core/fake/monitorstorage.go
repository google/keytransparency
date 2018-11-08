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
	"github.com/google/keytransparency/core/monitorstorage"
)

// MonitorStorage is an in-memory store for the monitoring results.
type MonitorStorage struct {
	store  map[int64]*monitorstorage.Result
	latest int64
}

// NewMonitorStorage returns an in-memory implementation of monitorstorage.Interface.
func NewMonitorStorage() *MonitorStorage {
	return &MonitorStorage{
		store: make(map[int64]*monitorstorage.Result),
	}
}

// Set stores the given data as a MonitoringResult which can be retrieved by Get.
func (s *MonitorStorage) Set(revision int64, r *monitorstorage.Result) error {
	if _, ok := s.store[revision]; ok {
		return monitorstorage.ErrAlreadyStored
	}
	s.store[revision] = r
	s.latest = revision
	return nil
}

// Get returns the Result for the given revision. It returns ErrNotFound if the revision does not exist.
func (s *MonitorStorage) Get(revision int64) (*monitorstorage.Result, error) {
	if result, ok := s.store[revision]; ok {
		return result, nil
	}
	return nil, monitorstorage.ErrNotFound
}

// LatestRevision is a convenience method to retrieve the latest stored revision.
func (s *MonitorStorage) LatestRevision() int64 {
	return s.latest
}
