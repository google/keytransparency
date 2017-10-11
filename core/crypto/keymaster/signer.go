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
	kmpb "github.com/google/keytransparency/core/proto/keymaster_proto"
)

type signer struct {
	signatures.Signer
	addedAt     time.Time // time when key is added to keymaster.
	description string
	status      kmpb.SigningKey_KeyStatus
}

// NewSigner creates a signer object from a private key.
func NewSigner(s signatures.Signer, addedAt time.Time,
	description string, status kmpb.SigningKey_KeyStatus) Signer {
	return &signer{
		Signer:      s,
		addedAt:     addedAt,
		description: description,
		status:      status,
	}
}

// NewSignerFromPEM parses a PEM formatted block and returns a signer object created
// using that block.
func NewSignerFromPEM(pemKey []byte) (Signer, error) {
	s, err := factory.NewSignerFromPEM(pemKey)
	if err != nil {
		return nil, err
	}
	return &signer{
		Signer:      s,
		addedAt:     time.Now(),
		description: "Signer created from PEM",
		status:      kmpb.SigningKey_ACTIVE,
	}, nil
}

// NewSignerFromRawKey creates a signer object from given raw key bytes.
func NewSignerFromRawKey(b []byte) (signatures.Signer, error) {
	s, err := factory.NewSignerFromBytes(b)
	if err != nil {
		return nil, err
	}
	return &signer{
		Signer:      s,
		addedAt:     time.Now(),
		description: "Signer created from raw key",
		status:      kmpb.SigningKey_ACTIVE,
	}, nil
}

// Status returns the status of the signer.
func (s *signer) Status() kmpb.SigningKey_KeyStatus {
	return s.status
}

// Activate activates the signer.
func (s *signer) Activate() {
	s.status = kmpb.SigningKey_ACTIVE
}

// Deactivate deactivates the signer.
func (s *signer) Deactivate() {
	s.status = kmpb.SigningKey_INACTIVE
}

// Deprecate sets the signer status to DEPRECATED.
func (s *signer) Deprecate() {
	s.status = kmpb.SigningKey_DEPRECATED
}

// Marshal marshals a signer object into a keymaster SigningKey message.
func (s *signer) Marshal() (*kmpb.SigningKey, error) {
	skPEM, err := s.PrivateKeyPEM()
	if err != nil {
		return nil, err
	}
	timestamp, err := ptypes.TimestampProto(s.addedAt)
	if err != nil {
		return nil, err
	}
	return &kmpb.SigningKey{
		Metadata: &kmpb.Metadata{
			KeyId:       s.KeyID(),
			AddedAt:     timestamp,
			Description: s.description,
		},
		KeyMaterial: skPEM,
		Status:      s.status,
	}, nil
}

// Clone creates a new instance of the signer object
func (s *signer) Clone() Signer {
	clone := *s
	return &clone
}
