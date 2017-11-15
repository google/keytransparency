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

// Package monitorstorage holds data produced by the monitor
package monitorstorage

import (
	"errors"

	"github.com/google/trillian"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

var (
	// ErrAlreadyStored is raised if the caller tries storing a response which
	// has already been stored.
	ErrAlreadyStored = errors.New("already stored epoch")
	// ErrNotFound is raised if the caller tries to retrieve data for an epoch
	// which has not been processed and stored yet.
	ErrNotFound = errors.New("data for epoch not found")
)

// Result stores all data
type Result struct {
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

// Interface is the interface for storing monitoring results.
type Interface interface {
	// Set stores the monitoring result for a specific epoch.
	Set(epoch int64, seenNanos int64, smr *trillian.SignedMapRoot, response *pb.GetMutationsResponse, errorList []error) error
	// Get retrieves the monitoring result for a specific epoch.
	Get(epoch int64) (*Result, error)
	// LatestEpoch returns the highest numbered epoch that has been processed.
	LatestEpoch() int64
}
