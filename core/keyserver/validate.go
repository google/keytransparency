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

	"github.com/google/keytransparency/core/crypto/commitments"
	"github.com/google/keytransparency/core/crypto/vrf"

	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
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
	// ErrWrongIndex occurs when the index in key value does not match the
	// output of VRF.
	ErrWrongIndex = errors.New("index does not match VRF")
	// ErrInvalidStart occurs when the start epoch of ListEntryHistoryRequest
	// is not valid (not in [1, currentEpoch]).
	ErrInvalidStart = errors.New("invalid start epoch")
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
// - Commitment in SignedEntryUpdate matches the serialized profile.
// - Profile is a valid.
func validateUpdateEntryRequest(in *tpb.UpdateEntryRequest, vrfPriv vrf.PrivateKey) error {
	kv := in.GetEntryUpdate().GetUpdate().GetKeyValue()
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		return err
	}

	// Verify Index / VRF
	index, _ := vrfPriv.Evaluate(vrf.UniqueID(in.UserId, in.AppId))
	if got, want := kv.Key, index[:]; !bytes.Equal(got, want) {
		return ErrWrongIndex
	}

	// Verify correct commitment to profile.
	committed := in.GetEntryUpdate().GetCommitted()
	if committed == nil {
		return ErrNoCommitted
	}
	if got, want := len(committed.Key), MinNonceLen; got < want {
		return ErrCommittedKeyLen
	}
	if err := commitments.Verify(in.UserId, in.AppId, entry.Commitment, committed); err != nil {
		return err
	}

	if err := validateKey(in.GetUserId(), in.GetAppId(), committed.GetData()); err != nil {
		return err
	}
	return nil
}

// validateListEntryHistoryRequest ensures that start epoch is in range [1,
// currentEpoch] and sets the page size if it is 0 or larger than what the server
// can return (due to reaching currentEpoch).
func validateListEntryHistoryRequest(in *tpb.ListEntryHistoryRequest, currentEpoch int64) error {
	if in.Start < 0 || in.Start > currentEpoch {
		return ErrInvalidStart
	}
	// TODO(ismail): make epochs consistently start from 0 and provide a function
	// such that callers don't need convert between starting 0 and 1.
	// Ensure a valid start epoch is provided if the Start parameter is not set.
	if in.Start == 0 {
		in.Start = defaultStartEpoch
	}

	switch {
	case in.PageSize < 0:
		return fmt.Errorf("Invalid page size")
	case in.PageSize == 0:
		in.PageSize = defaultPageSize
	case in.PageSize > maxPageSize:
		in.PageSize = maxPageSize
	}
	// Ensure in.PageSize does not exceed currentEpoch.
	if in.Start+int64(in.PageSize) > currentEpoch {
		in.PageSize = int32(currentEpoch - in.Start + 1)
	}
	return nil
}
