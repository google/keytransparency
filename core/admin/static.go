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

package admin

import (
	"fmt"

	"github.com/google/trillian/client"
)

// Static implements an admin interface for a static set of backends.
// Updates require a restart.
type Static struct {
	backends map[int64]*row
}

// row represents one domain backend.
type row struct {
	log client.VerifyingLogClient
}

// NewStatic returns an admin interface which returns trillian objects.
func NewStatic() *Static {
	return &Static{
		backends: make(map[int64]*row),
	}
}

// AddLog adds a particular log to Static.
func (s *Static) AddLog(logID int64, log client.VerifyingLogClient) error {
	s.backends[logID] = &row{
		log: log,
	}
	return nil
}

// LogClient returns the log client for logID.
func (s *Static) LogClient(logID int64) (client.VerifyingLogClient, error) {
	r, ok := s.backends[logID]
	if !ok {
		return nil, fmt.Errorf("No backend found for logID: %v", logID)
	}
	return r.log, nil
}
