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

package rsa

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"

	"github.com/google/keytransparency/core/crypto/signatures"

	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
)

const keySize = 3072

// signer generates signatures with a single key using RSA with SHA256 and 3072
// bits key size.
type signer struct {
	privKey *rsa.PrivateKey
	keyID   string
	rand    io.Reader
}

// GeneratePEMs generates a PEM-formatted pair of RSA public and private keys of
// size 3072 bits.
func GeneratePEMs() ([]byte, []byte, error) {
	skBytes, pkBytes, err := generateByteKeys()
	if err != nil {
		return nil, nil, err
	}
	skPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: skBytes,
		},
	)
	pkPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	return skPEM, pkPEM, nil
}

func generateByteKeys() ([]byte, []byte, error) {
	sk, err := rsa.GenerateKey(signatures.Rand, keySize)
	if err != nil {
		return nil, nil, err
	}
	skBytes := x509.MarshalPKCS1PrivateKey(sk)
	pkBytes, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		return nil, nil, err
	}
	return skBytes, pkBytes, nil
}

// NewSigner creates a signer object from a private key.
func NewSigner(pk crypto.Signer) (signatures.Signer, error) {
	privKey, ok := pk.(*rsa.PrivateKey)
	if !ok {
		return nil, signatures.ErrWrongKeyType
	}
	if privKey.PublicKey.N.BitLen() != keySize {
		return nil, signatures.ErrWrongKeyType
	}

	id, err := signatures.KeyID(&privKey.PublicKey)
	if err != nil {
		return nil, err
	}

	return &signer{
		privKey: privKey,
		keyID:   id,
		rand:    signatures.Rand,
	}, nil
}

// Sign generates a digital signature object.
func (s *signer) Sign(data interface{}) (*sigpb.DigitallySigned, error) {
	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	hashed := sha256.Sum256(j)

	sig, err := rsa.SignPKCS1v15(s.rand, s.privKey, crypto.SHA256, hashed[:])
	if err != nil {
		return nil, signatures.ErrSign
	}
	return &sigpb.DigitallySigned{
		HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		SignatureAlgorithm: sigpb.DigitallySigned_RSA,
		Signature:          sig,
	}, nil
}

// PublicKey returns the signer public key as keyspb.PublicKey proto message.
func (s *signer) PublicKey() (*keyspb.PublicKey, error) {
	return publicKey(&s.privKey.PublicKey)
}

// KeyID returns the ID of the associated public key.
func (s *signer) KeyID() string {
	return s.keyID
}

// PrivateKeyPEM marshals a signer object into a keymaster SigningKey message.
func (s *signer) PrivateKeyPEM() ([]byte, error) {
	skBytes := x509.MarshalPKCS1PrivateKey(s.privKey)
	skPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: skBytes,
		},
	)
	return skPEM, nil
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

// verifier verifies signatures using using RSA with SHA256 and 3072 bits key
// size.
type verifier struct {
	pubKey *rsa.PublicKey
	keyID  string
}

// NewVerifier creates a verifier from an RSA public key.
func NewVerifier(pk *rsa.PublicKey) (signatures.Verifier, error) {
	if pk.N.BitLen() != keySize {
		return nil, signatures.ErrWrongKeyType
	}
	id, err := signatures.KeyID(pk)
	if err != nil {
		return nil, err
	}

	return &verifier{
		pubKey: pk,
		keyID:  id,
	}, nil
}

// Verify checks the digital signature associated applied to data.
func (s *verifier) Verify(data interface{}, sig *sigpb.DigitallySigned) error {
	if sig == nil {
		return signatures.ErrMissingSig
	}
	if sig.HashAlgorithm != sigpb.DigitallySigned_SHA256 {
		log.Print("not SHA256 hash algorithm")
		return signatures.ErrVerify
	}
	if sig.SignatureAlgorithm != sigpb.DigitallySigned_RSA {
		log.Print("not RSA signature algorithm")
		return signatures.ErrVerify
	}

	j, err := json.Marshal(data)
	if err != nil {
		log.Print("json.Marshal failed")
		return signatures.ErrVerify
	}
	hashed := sha256.Sum256(j)

	return rsa.VerifyPKCS1v15(s.pubKey, crypto.SHA256, hashed[:], sig.Signature)
}

// PublicKey returns the verifier public key as keyspb.PublicKey proto message.
func (s *verifier) PublicKey() (*keyspb.PublicKey, error) {
	return publicKey(s.pubKey)
}

// KeyID returns the ID of the associated public key.
func (s *verifier) KeyID() string {
	return s.keyID
}

// PublicKeyPEM marshals a verifier object into a keymaster VerifyingKey message.
func (s *verifier) PublicKeyPEM() ([]byte, error) {
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
	return pkPEM, nil
}

// TODO(gdbelvin): rename to ToPublicProto
func publicKey(k *rsa.PublicKey) (*keyspb.PublicKey, error) {
	keyDER, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return &keyspb.PublicKey{Der: keyDER}, nil
}
