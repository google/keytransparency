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

	"github.com/google/keytransparency/core/crypto/signatures"

	"github.com/benlaurie/objecthash/go/objecthash"

	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"
)

// signer generates signatures with a single key using ECDSA P256.
type signer struct {
	privKey *ecdsa.PrivateKey
	keyID   string
	rand    io.Reader
}

// GeneratePEMs generates a PEM-formatted pair of P256 public and private keys.
func GeneratePEMs() ([]byte, []byte, error) {
	skBytes, pkBytes, err := generateByteKeys()
	if err != nil {
		return nil, nil, err
	}
	skPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
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
	p256Curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(p256Curve, signatures.Rand)
	if err != nil {
		return nil, nil, err
	}
	skBytes, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		return nil, nil, err
	}
	return skBytes, pkBytes, nil
}

// NewSigner creates a signer object from a private key.
func NewSigner(pk crypto.Signer) (signatures.Signer, error) {
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
	return &sigpb.DigitallySigned{
		HashAlgorithm:      sigpb.DigitallySigned_SHA256,
		SignatureAlgorithm: sigpb.DigitallySigned_ECDSA,
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

// PrivateKeyPEM marshals a signer object into a byte string.
func (s *signer) PrivateKeyPEM() ([]byte, error) {
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

// Clone creates a new instance of the signer object
func (s *signer) Clone() signatures.Signer {
	clone := *s
	return &clone
}

// verifier verifies signatures using ECDSA P256.
type verifier struct {
	pubKey *ecdsa.PublicKey
	keyID  string
}

// NewVerifier creates a verifier from a ECDSA public key.
func NewVerifier(pk *ecdsa.PublicKey) (signatures.Verifier, error) {
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
	if sig.SignatureAlgorithm != sigpb.DigitallySigned_ECDSA {
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

// PublicKey returns the verifier public key as keyspb.PublicKey proto message.
func (s *verifier) PublicKey() (*keyspb.PublicKey, error) {
	return publicKey(s.pubKey)
}

// KeyID returns the ID of the associated public key.
func (s *verifier) KeyID() string {
	return s.keyID
}

// Marshal marshals a verifier object into a keymaster VerifyingKey message.
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

// Clone creates a new instance of the verifier object
func (s *verifier) Clone() signatures.Verifier {
	clone := *s
	return &clone
}

func publicKey(k *ecdsa.PublicKey) (*keyspb.PublicKey, error) {
	keyDER, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return nil, err
	}
	return &keyspb.PublicKey{Der: keyDER}, nil
}
