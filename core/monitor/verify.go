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
// reconstruct clients can query.
package monitor

import (
	"time"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_types"
)

// VerifyResponse verifies a response received by the GetMutations API.
// Additionally to the response it takes a complete list of mutations. The list
// of received mutations may differ from those included in the initial response
// because of the max. page size.
func (m *Monitor) VerifyResponse(in *ktpb.GetMutationsResponse, allMuts []*ktpb.Mutation) *mopb.GetMonitoringResponse {
	resp := new(mopb.GetMonitoringResponse)
	seen := time.Now().UnixNano()
	resp.SeenTimestampNanos = seen

	// copy of received SMR:
	smr := *in.Smr
	resp.Smr = &smr
	// reset map's signature
	resp.Smr.Signature = nil

	return resp
}
