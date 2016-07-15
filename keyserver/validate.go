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
	"log"
	"time"

	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/vrf"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
)

// Maximum period of time to allow between CreationTime and server time.
const (
	MaxClockDrift = 5 * time.Minute
	PGPAppID      = "pgp"
	MinNonceLen   = 16
)

var (
	errNoAppID = errors.New("missing AppID")
)

// validateKey verifies:
// - appID is present.
// - Key is valid for its format.
func validateKey(userID, appID string, key []byte) error {
	if appID == "" {
		return errNoAppID
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
func validateUpdateEntryRequest(in *pb.UpdateEntryRequest, vrfPriv vrf.PrivateKey) error {
	// Unmarshal entry.
	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(in.GetEntryUpdate().GetUpdate().KeyValue, kv); err != nil {
		log.Printf("Error unmarshaling keyvalue: %v", err)
		return err
	}
	entry := new(pb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		log.Printf("Error unmarshaling entry: %v", err)
		return err
	}

	// Verify Index / VRF
	v, _ := vrfPriv.Evaluate([]byte(in.UserId))
	index := vrfPriv.Index(v)
	if got, want := kv.Key, index[:]; !bytes.Equal(got, want) {
		return grpc.Errorf(codes.InvalidArgument, "entry.Index=%v, want %v", got, want)
	}

	// Verify correct commitment to profile.
	p := new(pb.Profile)
	if err := proto.Unmarshal(in.GetEntryUpdate().Profile, p); err != nil {
		return grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal profile")
	}
	if got, want := len(in.GetEntryUpdate().CommitmentKey), MinNonceLen; got < want {
		return grpc.Errorf(codes.InvalidArgument, "len(CommitmentKey) = %v, want >= %v", got, want)
	}
	if err := commitments.VerifyName(in.UserId, in.GetEntryUpdate().CommitmentKey, in.GetEntryUpdate().Profile, entry.Commitment); err != nil {
		return err
	}

	// Validate the profile.
	if err := validateProfile(p, in.UserId); err != nil {
		return err
	}
	return nil
}

func validateProfile(p *pb.Profile, userID string) error {
	for appID, key := range p.GetKeys() {
		if err := validateKey(userID, appID, key); err != nil {
			return err
		}
	}
	return nil
}
