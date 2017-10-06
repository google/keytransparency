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

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/p256"
	"github.com/google/trillian/crypto/keyspb"

	ktrsa "github.com/google/keytransparency/core/crypto/signatures/rsa"
)

// NewSignerFromBytes creates a new signing object from the private key bytes.
func NewSignerFromBytes(b []byte) (signatures.Signer, error) {
	if k, err := x509.ParsePKCS1PrivateKey(b); err == nil {
		return ktrsa.NewSigner(k)
	} else if k, err := x509.ParseECPrivateKey(b); err == nil {
		return p256.NewSigner(k)
	}
	return nil, signatures.ErrUnimplemented
}

// NewSignerFromPEM creates a signer object based on information in given
// keymaster-related parameters.
func NewSignerFromPEM(pemKey []byte) (signatures.Signer, error) {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		return nil, signatures.ErrNoPEMFound
	}
	return NewSignerFromBytes(p.Bytes)
}

// NewVerifierFromBytes creates a verification object from the raw key bytes.
func NewVerifierFromBytes(b []byte) (signatures.Verifier, error) {
	k, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}

	switch pkType := k.(type) {
	case *rsa.PublicKey:
		return ktrsa.NewVerifier(pkType)
	case *ecdsa.PublicKey:
		return p256.NewVerifier(pkType)
	}
	return nil, signatures.ErrUnimplemented
}

// NewVerifierFromPEM creates a verifier object based on information in given
// keymaster-related parameters.
func NewVerifierFromPEM(pemKey []byte) (signatures.Verifier, error) {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		return nil, signatures.ErrNoPEMFound
	}
	return NewVerifierFromBytes(p.Bytes)
}

// NewVerifierFromKey creates a verifier object from a PublicKey proto object.
func NewVerifierFromKey(key *keyspb.PublicKey) (signatures.Verifier, error) {
	return NewVerifierFromBytes(key.Der)
}
