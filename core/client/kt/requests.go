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

package kt

import (
	"fmt"

	"github.com/google/keytransparency/core/commitments"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/vrf"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian/crypto/sigpb"
)

// CreateUpdateEntryRequest creates UpdateEntryRequest given GetEntryResponse,
// user ID and a profile.
func CreateUpdateEntryRequest(getResp *tpb.GetEntryResponse, vrf vrf.PublicKey, userID string, profile *tpb.Profile, signers []signatures.Signer, authorizedKeys []*tpb.PublicKey) (*tpb.UpdateEntryRequest, error) {
	// Extract index from a prior GetEntry call.
	index := vrf.Index(getResp.Vrf)
	prevEntry := new(tpb.Entry)
	if err := proto.Unmarshal(getResp.GetLeafProof().GetLeaf().GetLeafValue(), prevEntry); err != nil {
		return nil, fmt.Errorf("Error unmarshaling Entry from leaf proof: %v", err)
	}

	// Commit to profile.
	profileData, err := proto.Marshal(profile)
	if err != nil {
		return nil, fmt.Errorf("Unexpected profile marshaling error: %v", err)
	}
	commitment, committed, err := commitments.Commit(userID, profileData)
	if err != nil {
		return nil, err
	}

	// Create new Entry.
	keys := authorizedKeys
	if len(keys) == 0 {
		keys = prevEntry.AuthorizedKeys
	}
	entry := &tpb.Entry{
		Commitment:     commitment,
		AuthorizedKeys: keys,
	}

	// Sign Entry.
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, err
	}
	kv := &tpb.KeyValue{
		Key:   index[:],
		Value: entryData,
	}
	sigs, err := generateSignatures(kv, signers)
	if err != nil {
		return nil, err
	}
	previous := objecthash.ObjectHash(getResp.GetLeafProof().GetLeaf().GetLeafValue())
	signedkv := &tpb.SignedKV{
		KeyValue:   kv,
		Signatures: sigs,
		Previous:   previous[:],
	}

	return &tpb.UpdateEntryRequest{
		UserId: userID,
		EntryUpdate: &tpb.EntryUpdate{
			Update:    signedkv,
			Committed: committed,
		},
	}, err
}

func generateSignatures(data interface{}, signers []signatures.Signer) (map[string]*sigpb.DigitallySigned, error) {
	sigs := make(map[string]*sigpb.DigitallySigned)
	for _, signer := range signers {
		sig, err := signer.Sign(data)
		if err != nil {
			return nil, err
		}
		sigs[signer.KeyID()] = sig
	}
	return sigs, nil
}
