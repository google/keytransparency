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
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"

	"github.com/google/key-transparency/core/proto/ctmap"

	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
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
)

// Signer represents an object that can generate signatures with a single key.
type Signer interface {
	// Sign generates a digital signature object.
	Sign(interface{}) (*ctmap.DigitallySigned, error)
	// KeyID returns the ID of the associated public key.
	KeyID() string
}

// Verifier represents an object that can verify signatures with a single key.
type Verifier interface {
	// Verify checks the digital signature associated applied to data.
	Verify(interface{}, *ctmap.DigitallySigned) error
	// KeyID returns the ID of the associated public key.
	KeyID() string
}

// SignerFromPEM parses a PEM formatted block and returns a signer object created
// using that block.
func SignerFromPEM(rand io.Reader, b []byte) (Signer, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, ErrNoPEMFound
	}
	return signerFromBytes(rand, p.Bytes)
}

func signerFromBytes(rand io.Reader, b []byte) (Signer, error) {
	if _, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return nil, ErrUnimplemented
	} else if k, err := x509.ParseECPrivateKey(b); err == nil {
		return newP256Signer(rand, k)
	}
	return nil, ErrUnimplemented
}

// VerifierFromPEM parses a PEM formatted block and returns a verifier object
// created using that block.
func VerifierFromPEM(b []byte) (Verifier, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, ErrNoPEMFound
	}
	return verifierFromBytes(p.Bytes)
}

func verifierFromBytes(b []byte) (Verifier, error) {
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}

	switch pkType := k.(type) {
	case *rsa.PublicKey:
		return nil, ErrUnimplemented
	case *ecdsa.PublicKey:
		return newP256Verifier(pkType)
	}
	return nil, ErrUnimplemented
}

// VerifierFromKey creates a verifier object from a PublicKey proto object.
func VerifierFromKey(key *tpb.PublicKey) (Verifier, error) {
	switch {
	case key.GetEd25519() != nil:
		return nil, ErrUnimplemented
	case key.GetRsaVerifyingSha256_3072() != nil:
		return nil, ErrUnimplemented
	case key.GetEcdsaVerifyingP256() != nil:
		return verifierFromBytes(key.GetEcdsaVerifyingP256())
	default:
		return nil, errors.New("public key not found")
	}
}

// keyID is the hex digits of the SHA256 of the public pem.
func keyID(k crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}
	id := sha256.Sum256(pubBytes)
	return hex.EncodeToString(id[:]), nil
}
