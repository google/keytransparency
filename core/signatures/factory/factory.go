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

package factory

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"time"

	"github.com/google/key-transparency/core/signatures"
	"github.com/google/key-transparency/core/signatures/p256"

	kmpb "github.com/google/key-transparency/core/proto/keymaster"
	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

// NewSigner creates a signer object based on information in given
// keymaster-related parameters.
func NewSigner(pemKey []byte, addedAt time.Time, description string, status kmpb.SigningKey_KeyStatus) (signatures.Signer, error) {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		return nil, signatures.ErrNoPEMFound
	}
	return signerFromBytes(p.Bytes, addedAt, description, status)
}

// SignerFromPEM parses a PEM formatted block and returns a signer object created
// using that block.
func SignerFromPEM(pemKey []byte) (signatures.Signer, error) {
	return NewSigner(pemKey, time.Now(), "Signer created from PEM", kmpb.SigningKey_ACTIVE)
}

// SignerFromRawKey creates a signer object from given raw key bytes.
func SignerFromRawKey(rand io.Reader, b []byte) (Signer, error) {
	return signerFromBytes(rand, b, time.Now(), "Signer created from raw key", kmpb.SigningKey_ACTIVE)
}

func signerFromBytes(b []byte, addedAt time.Time, description string, status kmpb.SigningKey_KeyStatus) (signatures.Signer, error) {
	if _, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return nil, signatures.ErrUnimplemented
	} else if k, err := x509.ParseECPrivateKey(b); err == nil {
		return p256.NewSigner(k, addedAt, description, status)
	}
	return nil, signatures.ErrUnimplemented
}

// NewVerifier creates a verifier object based on information in given
// keymaster-related parameters.
func NewVerifier(pemKey []byte, addedAt time.Time, description string, status kmpb.VerifyingKey_KeyStatus) (signatures.Verifier, error) {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		return nil, signatures.ErrNoPEMFound
	}
	return verifierFromBytes(p.Bytes, addedAt, description, status)
}

// VerifierFromPEM parses a PEM formatted block and returns a verifier object
// created using that block.
func VerifierFromPEM(pemKey []byte) (signatures.Verifier, error) {
	return NewVerifier(pemKey, time.Now(), "Verifier created from PEM", kmpb.VerifyingKey_ACTIVE)
}

// VerifierFromRawKey creates a verifier object from given raw key bytes.
func VerifierFromRawKey(b []byte) (Verifier, error) {
	return verifierFromBytes(b, time.Now(), "Verifier created from raw key", kmpb.VerifyingKey_ACTIVE)
}

// VerifierFromKey creates a verifier object from a PublicKey proto object.
func VerifierFromKey(key *tpb.PublicKey) (signatures.Verifier, error) {
	switch {
	case key.GetEd25519() != nil:
		return nil, signatures.ErrUnimplemented
	case key.GetRsaVerifyingSha256_3072() != nil:
		return nil, signatures.ErrUnimplemented
	case key.GetEcdsaVerifyingP256() != nil:
		return verifierFromBytes(key.GetEcdsaVerifyingP256(), time.Now(), "Verifier created from PublicKey", kmpb.VerifyingKey_ACTIVE)
	default:
		return nil, errors.New("public key not found")
	}
}

func verifierFromBytes(b []byte, addedAt time.Time, description string, status kmpb.VerifyingKey_KeyStatus) (signatures.Verifier, error) {
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}

	switch pkType := k.(type) {
	case *rsa.PublicKey:
		return nil, signatures.ErrUnimplemented
	case *ecdsa.PublicKey:
		return p256.NewVerifier(pkType, addedAt, description, status)
	}
	return nil, signatures.ErrUnimplemented
}
