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

	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/trillian/crypto/keyspb"
)

func (v *Verifier) index(vrfProof []byte, domainID, appID, userID string) ([]byte, error) {
	uid := vrf.UniqueID(userID, appID)
	index, err := v.vrf.ProofToHash(uid, vrfProof)
	if err != nil {
		return nil, fmt.Errorf("vrf.ProofToHash(%v, %v): %v", appID, userID, err)
	}
	return index[:], nil
}

// NewMutation creates a Mutation given the userID, desired state, and previous entry.
func (v *Verifier) NewMutation(
	domainID, appID, userID string,
	profileData []byte, authorizedKeys []*keyspb.PublicKey,
	vrfProof, oldLeaf []byte) (
	*entry.Mutation, error) {

	index, err := v.index(vrfProof, domainID, appID, userID)
	if err != nil {
		return nil, err
	}
	mutation := entry.NewMutation(index, domainID, appID, userID)
	if err := mutation.SetPrevious(oldLeaf, true); err != nil {
		return nil, err
	}

	if err := mutation.SetCommitment(profileData); err != nil {
		return nil, err
	}

	if len(authorizedKeys) != 0 {
		if err := mutation.ReplaceAuthorizedKeys(authorizedKeys); err != nil {
			return nil, err
		}
	}

	return mutation, nil
}
