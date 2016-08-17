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

package keyserver

// validate performs correctness checking on each v2 message type.

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	"github.com/google/key-transparency/core/commitments"
	"github.com/google/key-transparency/core/vrf"

	"github.com/golang/protobuf/proto"

	pbtypes "github.com/google/key-transparency/core/proto/kt_v1_types"
)

// Maximum period of time to allow between CreationTime and server time.
const (
	MaxClockDrift = 5 * time.Minute
	PGPAppID      = "pgp"
	MinNonceLen   = 16
)

var (
	// ErrNoAppID occurs when the app id is missing.
	ErrNoAppID = errors.New("missing AppID")
	// ErrNoCommitted occurs when the committed field is missing.
	ErrNoCommitted = errors.New("missing commitment")
	// ErrCommittedKeyLen occurs when the committed key is too small.
	ErrCommittedKeyLen = errors.New("committed.key is too small")
	// ErrWrongIndex occurs when the index in key value does not match the output of VRF.
	ErrWrongIndex = errors.New("index does not match vrf")
)

// validateKey verifies:
// - appID is present.
// - Key is valid for its format.
func validateKey(userID, appID string, key []byte) error {
	if appID == "" {
		return ErrNoAppID
	}
	if appID == PGPAppID {
		pgpUserID := fmt.Sprintf("<%v>", userID)
		if _, err := validatePGP(pgpUserID, bytes.NewBuffer(key)); err != nil {
			return err
		}
	}
	return nil
}

// validateUpdateEntryRequest verifies
// - Commitment in SignedEntryUpdate maches the serialized profile.
// - Profile is a valid.
func validateUpdateEntryRequest(in *pbtypes.UpdateEntryRequest, vrfPriv vrf.PrivateKey) error {
	// Unmarshal entry.
	kv := new(pbtypes.KeyValue)
	if err := proto.Unmarshal(in.GetEntryUpdate().GetUpdate().KeyValue, kv); err != nil {
		return err
	}
	entry := new(pbtypes.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		return err
	}

	// Verify Index / VRF
	v, _ := vrfPriv.Evaluate([]byte(in.UserId))
	index := vrfPriv.Index(v)
	if got, want := kv.Key, index[:]; !bytes.Equal(got, want) {
		return ErrWrongIndex
	}

	// Verify correct commitment to profile.
	if in.GetEntryUpdate().GetCommitted() == nil {
		return ErrNoCommitted
	}
	p := new(pbtypes.Profile)
	if err := proto.Unmarshal(in.GetEntryUpdate().GetCommitted().Data, p); err != nil {
		return err
	}
	if got, want := len(in.GetEntryUpdate().GetCommitted().Key), MinNonceLen; got < want {
		return ErrCommittedKeyLen
	}
	if err := commitments.Verify(in.UserId, entry.Commitment, in.GetEntryUpdate().Committed); err != nil {
		return err
	}

	// Validate the profile.
	if err := validateProfile(p, in.UserId); err != nil {
		return err
	}
	return nil
}

func validateProfile(p *pbtypes.Profile, userID string) error {
	for appID, key := range p.GetKeys() {
		if err := validateKey(userID, appID, key); err != nil {
			return err
		}
	}
	return nil
}
