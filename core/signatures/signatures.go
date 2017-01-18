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

package signatures

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"

	"github.com/google/keytransparency/core/proto/ctmap"
	kmpb "github.com/google/keytransparency/core/proto/keymaster"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

var (
	// ErrWrongKeyType occurs when a key is not an ECDSA key.
	ErrWrongKeyType = errors.New("not an ECDSA key")
	// ErrPointNotOnCurve occurs when a public key is not on the curve.
	ErrPointNotOnCurve = errors.New("point is not on the P256 curve")
	// ErrMissingSig occurs when the Verify function is called with a nil signature.
	ErrMissingSig = errors.New("missing signature")
	// ErrNoPEMFound occurs when attempting to parse a non PEM data structure.
	ErrNoPEMFound = errors.New("no PEM block found")
	// ErrSign occurs whenever signature generation fails.
	ErrSign = errors.New("signature generation failed")
	// ErrVerify occurs whenever signature verification fails.
	ErrVerify = errors.New("signature verification failed")
	// ErrUnimplemented occurs when a signature scheme is not implemented.
	ErrUnimplemented = errors.New("scheme is unimplemented")
	// Rand is the PRNG reader. It can be overwritten in tests.
	Rand = rand.Reader
)

// Signer represents an object that can generate signatures with a single key.
type Signer interface {
	// Sign generates a digital signature object.
	Sign(interface{}) (*ctmap.DigitallySigned, error)
	// PublicKey returns the signer public key as tpb.PublicKey proto
	// message.
	PublicKey() (*tpb.PublicKey, error)
	// KeyID returns the ID of the associated public key.
	KeyID() string
	// Status returns the status of the signer.
	Status() kmpb.SigningKey_KeyStatus
	// Activate activates the signer.
	Activate()
	// Deactivate deactivates the signer.
	Deactivate()
	// Deprecate sets the signer status to DEPRECATED.
	Deprecate()
	// Marshal marshals a signer object into a keymaster SigningKey message.
	Marshal() (*kmpb.SigningKey, error)
	// PublicKeyPEM returns the PEM-formatted public key of this signer.
	PublicKeyPEM() ([]byte, error)
	// Clone creates a new instance of the signer object
	Clone() Signer
}

// Verifier represents an object that can verify signatures with a single key.
type Verifier interface {
	// Verify checks the digital signature associated applied to data.
	Verify(interface{}, *ctmap.DigitallySigned) error
	// PublicKey returns the verifier public key as tpb.PublicKey proto
	// message.
	PublicKey() (*tpb.PublicKey, error)
	// KeyID returns the ID of the associated public key.
	KeyID() string
	// Status returns the status of the verifier.
	Status() kmpb.VerifyingKey_KeyStatus
	// Deprecate sets the verifier status to DEPRECATED.
	Deprecate()
	// Marshal marshals a verifier object into a keymaster VerifyingKey
	// message.
	Marshal() (*kmpb.VerifyingKey, error)
	// Clone creates a new instance of the verifier object
	Clone() Verifier
}

// KeyID is the hex digits of the SHA256 of the public pem.
func KeyID(k crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}
	id := sha256.Sum256(pubBytes)
	return hex.EncodeToString(id[:]), nil
}
