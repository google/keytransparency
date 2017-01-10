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

package p256

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"time"

	"github.com/google/key-transparency/core/signatures"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/key-transparency/core/proto/ctmap"

	kmpb "github.com/google/key-transparency/core/proto/keymaster"
	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

// signer generates signatures with a single key using ECDSA P256.
type signer struct {
	privKey     *ecdsa.PrivateKey
	keyID       string
	rand        io.Reader
	addedAt     time.Time // time when key is added to keystore.
	description string
	status      kmpb.SigningKey_KeyStatus
}

// NewSigner creates a signer object from a private key.
func NewSigner(pk crypto.Signer, addedAt time.Time, description string, status kmpb.SigningKey_KeyStatus) (signatures.Signer, error) {
	var privKey *ecdsa.PrivateKey
	switch pkType := pk.(type) {
	case *ecdsa.PrivateKey:
		params := *(pkType.Params())
		if params != *elliptic.P256().Params() {
			return nil, signatures.ErrPointNotOnCurve
		}
		if !elliptic.P256().IsOnCurve(pkType.X, pkType.Y) {
			return nil, signatures.ErrPointNotOnCurve
		}
		privKey = pkType
	default:
		return nil, signatures.ErrWrongKeyType
	}

	id, err := signatures.KeyID(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &signer{
		privKey:     privKey,
		keyID:       id,
		rand:        signatures.Rand,
		addedAt:     addedAt,
		description: description,
		status:      status,
	}, nil
}

// Sign generates a digital signature object.
func (s *signer) Sign(data interface{}) (*ctmap.DigitallySigned, error) {
	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	hash := objecthash.CommonJSONHash(string(j))

	var ecSig struct {
		R, S *big.Int
	}
	ecSig.R, ecSig.S, err = ecdsa.Sign(s.rand, s.privKey, hash[:])
	if err != nil {
		log.Print("signature generation failed")
		return nil, signatures.ErrSign
	}
	sig, err := asn1.Marshal(ecSig)
	if err != nil {
		log.Print("failed to marshal ECDSA signature")
		return nil, signatures.ErrSign
	}
	return &ctmap.DigitallySigned{
		HashAlgorithm: ctmap.DigitallySigned_SHA256,
		SigAlgorithm:  ctmap.DigitallySigned_ECDSA,
		Signature:     sig,
	}, nil
}

// PublicKey returns the signer public key as tpb.PublicKey proto
// message.
func (s *signer) PublicKey() (*tpb.PublicKey, error) {
	return publicKey(&s.privKey.PublicKey)
}

// KeyID returns the ID of the associated public key.
func (s *signer) KeyID() string {
	return s.keyID
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

// Deprecate sets the signer status to DEPRECATED.D
func (s *signer) Deprecate() {
	s.status = kmpb.SigningKey_DEPRECATED
}

// Marshal marshals a signer object into a keymaster SigningKey message.
func (s *signer) Marshal() (*kmpb.SigningKey, error) {
	skBytes, err := x509.MarshalECPrivateKey(s.privKey)
	if err != nil {
		return nil, err
	}
	skPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: skBytes,
		},
	)
	timestamp, err := ptypes.TimestampProto(s.addedAt)
	if err != nil {
		return nil, err
	}
	return &kmpb.SigningKey{
		Metadata: &kmpb.Metadata{
			KeyId:       s.keyID,
			AddedAt:     timestamp,
			Description: s.description,
		},
		KeyMaterial: skPEM,
		Status:      s.status,
	}, nil
}

// PublicKeyPEM returns the PEM-formatted public key of this signer.
func (s *signer) PublicKeyPEM() ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(s.privKey.Public())
	if err != nil {
		return nil, err
	}
	pkPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	return pkPEM, nil
}

// Clone creates a new instance of the signer object
func (s *signer) Clone() signatures.Signer {
	clone := *s
	return &clone
}

// verifier verifies signatures using ECDSA P256.
type verifier struct {
	pubKey      *ecdsa.PublicKey
	keyID       string
	addedAt     time.Time // time when key is added to keystore.
	description string
	status      kmpb.VerifyingKey_KeyStatus
}

// NewVerifier creates a verifier from a ECDSA public key.
func NewVerifier(pk *ecdsa.PublicKey, addedAt time.Time, description string, status kmpb.VerifyingKey_KeyStatus) (signatures.Verifier, error) {
	params := *(pk.Params())
	if params != *elliptic.P256().Params() {
		return nil, signatures.ErrPointNotOnCurve
	}
	if !elliptic.P256().IsOnCurve(pk.X, pk.Y) {
		return nil, signatures.ErrPointNotOnCurve
	}
	id, err := signatures.KeyID(pk)
	if err != nil {
		return nil, err
	}

	return &verifier{
		pubKey:      pk,
		keyID:       id,
		addedAt:     addedAt,
		description: description,
		status:      status,
	}, nil
}

// Verify checks the digital signature associated applied to data.
func (s *verifier) Verify(data interface{}, sig *ctmap.DigitallySigned) error {
	if sig == nil {
		return signatures.ErrMissingSig
	}
	if sig.HashAlgorithm != ctmap.DigitallySigned_SHA256 {
		log.Print("not SHA256 hash algorithm")
		return signatures.ErrVerify
	}
	if sig.SigAlgorithm != ctmap.DigitallySigned_ECDSA {
		log.Print("not ECDSA signature algorithm")
		return signatures.ErrVerify
	}

	j, err := json.Marshal(data)
	if err != nil {
		log.Print("json.Marshal failed")
		return signatures.ErrVerify
	}
	hash := objecthash.CommonJSONHash(string(j))

	var ecdsaSig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig.Signature, &ecdsaSig)
	if err != nil {
		log.Print("failed to unmarshal ECDSA signature")
		return signatures.ErrVerify
	}
	if len(rest) != 0 {
		log.Print("extra data found after signature")
		return signatures.ErrVerify
	}

	if !ecdsa.Verify(s.pubKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		log.Print("failed to verify ECDSA signature")
		return signatures.ErrVerify
	}
	return nil
}

// PublicKey returns the verifier public key as tpb.PublicKey proto
// message.
func (s *verifier) PublicKey() (*tpb.PublicKey, error) {
	return publicKey(s.pubKey)
}

// KeyID returns the ID of the associated public key.
func (s *verifier) KeyID() string {
	return s.keyID
}

func publicKey(k *ecdsa.PublicKey) (*tpb.PublicKey, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return &tpb.PublicKey{
		KeyType: &tpb.PublicKey_EcdsaVerifyingP256{
			EcdsaVerifyingP256: pubBytes,
		},
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
	pkBytes, err := x509.MarshalPKIXPublicKey(s.pubKey)
	if err != nil {
		return nil, err
	}
	pkPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	timestamp, err := ptypes.TimestampProto(s.addedAt)
	if err != nil {
		return nil, err
	}
	return &kmpb.VerifyingKey{
		Metadata: &kmpb.Metadata{
			KeyId:       s.keyID,
			AddedAt:     timestamp,
			Description: s.description,
		},
		KeyMaterial: pkPEM,
		Status:      s.status,
	}, nil
}

// Clone creates a new instance of the verifier object
func (s *verifier) Clone() signatures.Verifier {
	clone := *s
	return &clone
}
