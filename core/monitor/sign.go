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

package monitor

import (
	"fmt"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	tpb "github.com/google/trillian"
)

func (m *Monitor) signMapRoot(in *pb.GetMutationsResponse) (*tpb.SignedMapRoot, error) {
	// copy of received SMR:
	smr := *in.Smr
	smr.Signature = nil

	sig, err := m.signer.SignObject(smr)
	if err != nil {
		return nil, fmt.Errorf("SignObject(): %v", err)
	}
	smr.Signature = sig

	return &smr, nil
}
