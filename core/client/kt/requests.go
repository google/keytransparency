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

// Package kt holds Key Transparency message generation and verification routines.
package kt

import (
	"fmt"

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/trillian/crypto/keyspb"

	"github.com/google/trillian"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

// CreateUpdateEntryRequest creates UpdateEntryRequest given GetEntryResponse,
// user ID and a profile.
func CreateUpdateEntryRequest(
	trusted *trillian.SignedLogRoot, getResp *tpb.GetEntryResponse,
	vrfPub vrf.PublicKey, domainID, userID, appID string, profileData []byte,
	signers []signatures.Signer, authorizedKeys []*keyspb.PublicKey) (*tpb.UpdateEntryRequest, error) {
	// Extract index from a prior GetEntry call.
	index, err := vrfPub.ProofToHash(vrf.UniqueID(userID, appID), getResp.VrfProof)
	if err != nil {
		return nil, fmt.Errorf("ProofToHash(): %v", err)
	}

	oldLeaf := getResp.GetLeafProof().GetLeaf().GetLeafValue()
	mutation, err := entry.NewMutation(oldLeaf, index[:], userID, appID)
	if err != nil {
		return nil, fmt.Errorf("Error unmarshaling Entry from leaf proof: %v", err)
	}

	// Update Commitment.
	if err := mutation.SetCommitment(profileData); err != nil {
		return nil, err
	}

	// Update Authorization.
	if len(authorizedKeys) != 0 {
		if err := mutation.ReplaceAuthorizedKeys(authorizedKeys); err != nil {
			return nil, err
		}
	}

	// Sign Entry
	updateRequest, err := mutation.SerializeAndSign(signers)
	if err != nil {
		return nil, err
	}
	updateRequest.DomainId = domainID
	updateRequest.FirstTreeSize = trusted.TreeSize
	return updateRequest, nil
}
