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

package client

import (
	"log"

	"github.com/google/e2e-key-server/commitments"

	"github.com/golang/protobuf/proto"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
)

func (c *Client) verifyGetEntryResponse(userID string, in *pb.GetEntryResponse) bool {
	// Verify VRF proof.
	if !c.vrf.Verify([]byte(userID), in.Vrf, in.VrfProof) {
		log.Printf("Vrf verification failed.")
		return false
	}
	index := c.vrf.Index(in.Vrf)

	// TODO: Verify STH signatures
	// TODO: Verify Consistency Proof
	if !c.mapc.AdvanceSEH(in.GetSth(), in.GetConsistencyProof()) {
		return false
	}

	// Verify leaf proof.
	if !c.mapc.VerifyLeafProof(index[:], in.GetLeafProof()) {
		log.Printf("Failed verifable map inclusion proof")
		return false
	}

	// Verify profile commitment.
	if in.Profile != nil {
		entry := new(pb.Entry)
		if err := proto.Unmarshal(in.GetLeafProof().LeafData, entry); err != nil {
			log.Printf("Error unmarshaling entry: %v", err)
			return false
		}

		if err := commitments.VerifyName(userID, in.CommitmentKey, in.Profile, entry.Commitment); err != nil {
			log.Printf("Invalid profile commitment.")
			return false
		}
	}

	return true
}
