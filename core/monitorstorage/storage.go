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
	"time"

	"github.com/google/trillian"
)

var (
	// ErrAlreadyStored is raised if the caller tries storing a response which
	// has already been stored.
	ErrAlreadyStored = errors.New("already stored revision")
	// ErrNotFound is raised if the caller tries to retrieve data for an revision
	// which has not been processed and stored yet.
	ErrNotFound = errors.New("data for revision not found")
)

// Result describes the monitor's attempt to verify the complete transition from
// SignedMapRoot (SMR) revision T to revision T+1, having been supplied the set
// of mutations by which to transform SMR T into SMR T+1.
//
// Result contains the monitor's signature on SMR T if the monitor believes that
// the transition from T to T+1 is fully correct. It also contains that time at which
// the monitor observed SMR, and in cases where the verification did not succeed, a
// list of errors describing the observed problems, and a collection of data by which
// others can attempt the same verification.
type Result struct {
	// Smr contains the map root signed by the monitor in case all verifications
	// have passed.
	Smr *trillian.SignedMapRoot
	// Seen is the timestamp at which the mutations response has been received.
	Seen time.Time
	// Errors contains a string representation of the verifications steps that
	// failed.
	Errors []error
}

// Interface is the interface that stores and retrieves monitoring results.
// TODO(gbelvin): make multi-tenant.
type Interface interface {
	// Set stores the monitoring result for a specific revision.
	Set(revision int64, r *Result) error
	// Get retrieves the monitoring result for a specific revision.
	Get(revision int64) (*Result, error)
	// LatestRevision returns the highest numbered revision that has been processed.
	LatestRevision() int64
}
