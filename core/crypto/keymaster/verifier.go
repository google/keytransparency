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

package keymaster

import (
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	kmpb "github.com/google/keytransparency/core/proto/keymaster"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

type verifier struct {
	signatures.Verifier
	addedAt     time.Time // time when key is added to keymaster.
	description string
	status      kmpb.VerifyingKey_KeyStatus
}

// NewVerifier creates a verifier from a ECDSA public key.
func NewVerifier(v signatures.Verifier, addedAt time.Time,
	description string, status kmpb.VerifyingKey_KeyStatus) Verifier {
	return &verifier{
		Verifier:    v,
		addedAt:     addedAt,
		description: description,
		status:      status,
	}
}

// NewVerifierFromPEM parses a PEM formatted block and returns a verifier object
// created using that block.
func NewVerifierFromPEM(pemKey []byte) (Verifier, error) {
	v, err := factory.NewVerifierFromPEM(pemKey)
	if err != nil {
		return nil, err
	}
	return &verifier{
		Verifier:    v,
		addedAt:     time.Now(),
		description: "Verifier created from from PEM",
		status:      kmpb.VerifyingKey_ACTIVE,
	}, nil
}

// NewVerifierFromKey creates a verifier object from a PublicKey proto object.
func NewVerifierFromKey(key *tpb.PublicKey) (Verifier, error) {
	v, err := factory.NewVerifierFromKey(key)
	if err != nil {
		return nil, err
	}
	return &verifier{
		Verifier:    v,
		addedAt:     time.Now(),
		description: "Verifier created from PublicKey",
		status:      kmpb.VerifyingKey_ACTIVE,
	}, nil
}

// NewVerifierFromRawKey creates a verifier object from given raw key bytes.
func NewVerifierFromRawKey(b []byte) (Verifier, error) {
	v, err := factory.NewVerifierFromBytes(b)
	if err != nil {
		return nil, err
	}
	return &verifier{
		Verifier:    v,
		addedAt:     time.Now(),
		description: "Verifier created from raw key",
		status:      kmpb.VerifyingKey_ACTIVE,
	}, nil
}

// Status returns the status of the verifier.
func (s *verifier) Status() kmpb.VerifyingKey_KeyStatus {
	return s.status
}

// Deprecate sets the verifier status to DEPRECATED.
func (s *verifier) Deprecate() {
	s.status = kmpb.VerifyingKey_DEPRECATED
}

// Marshal marshals a verifier object into a keymaster VerifyingKey message.
func (s *verifier) Marshal() (*kmpb.VerifyingKey, error) {
	pkBytes, err := s.PublicKeyPEM()
	if err != nil {
		return nil, err
	}
	timestamp, err := ptypes.TimestampProto(s.addedAt)
	if err != nil {
		return nil, err
	}
	return &kmpb.VerifyingKey{
		Metadata: &kmpb.Metadata{
			KeyId:       s.KeyID(),
			AddedAt:     timestamp,
			Description: s.description,
		},
		KeyMaterial: pkBytes,
		Status:      s.status,
	}, nil
}

// Clone creates a new instance of the verifier object
func (s *verifier) Clone() Verifier {
	clone := *s
	return &clone
}
