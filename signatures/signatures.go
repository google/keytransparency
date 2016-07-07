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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"

	"github.com/benlaurie/objecthash/go/objecthash"

	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
)

var (
	ErrWrongKeyType       = errors.New("Not an ECDSA key")
	ErrPointNotOnCurve    = errors.New("Point is not on the P256 curve")
	ErrWrongHashAlgo      = errors.New("Not the SHA256 hash algorithm")
	ErrWrongSignatureAlgo = errors.New("Not the ECDSA signature algorithm")
	ErrExtraDataAfterSig  = errors.New("Extra data found after signature")
	ErrVerificaionFailed  = errors.New("Failed to verify ECDSA signature")
)

type SignatureSigner struct {
	privKey crypto.PrivateKey
	KeyName string
}

// GenerateKeyPair creates a new random keypair and returns the wrapped signer and verifier.
func GenerateKeyPair() (*SignatureSigner, *SignatureVerifier, error) {
	pubkeyCurve := elliptic.P256()
	privatekey := new(ecdsa.PrivateKey)
	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sig, err := NewSignatureSigner(privatekey)
	if err != nil {
		return nil, nil, err
	}
	ver, err := NewSignatureVerifier(privatekey.Public())
	if err != nil {
		return nil, nil, err
	}
	return sig, ver, nil
}

// PrivateKeyFromPEM parses a PEM formatted block and returns the private key contained within and any remaining unread bytes, or an error.
func PrivateKeyFromPEM(b []byte) (crypto.Signer, []byte, error) {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil, rest, fmt.Errorf("no PEM block found in %s", string(b))
	}
	k, err := x509.ParseECPrivateKey(p.Bytes)
	return k, rest, err
}

// KeyName is the first 8 hex digits of the SHA256 of the public pem.
func KeyName(k crypto.PublicKey) (string, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(k)
	if err != nil {
		return "", err
	}
	id := sha256.Sum256(pubBytes)
	return hex.EncodeToString(id[:])[:8], nil
}

func NewSignatureSigner(pk crypto.Signer) (*SignatureSigner, error) {
	switch pkType := pk.(type) {
	case *ecdsa.PrivateKey:
		params := *(pkType.Params())
		if params != *elliptic.P256().Params() {
			e := fmt.Errorf("public is ECDSA, but not on the P256 curve")
			return nil, e
		}
	default:
		return nil, fmt.Errorf("Unsupported public key type %v", pkType)
	}

	id, err := KeyName(pk.Public())
	if err != nil {
		return nil, err
	}

	return &SignatureSigner{
		privKey: pk,
		KeyName: id,
	}, nil
}

func (s SignatureSigner) Sign(data interface{}) (*ctmap.DigitallySigned, error) {
	j, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	hash := objecthash.CommonJSONHash(string(j))

	ecdsaKey, ok := s.privKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, ErrWrongKeyType
	}
	var ecSig struct {
		R, S *big.Int
	}
	ecSig.R, ecSig.S, err = ecdsa.Sign(rand.Reader, ecdsaKey, hash[:])
	if err != nil {
		return nil, err
	}
	sig, err := asn1.Marshal(ecSig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA signature: %v", err)
	}
	return &ctmap.DigitallySigned{
		HashAlgorithm: ctmap.DigitallySigned_SHA256,
		SigAlgorithm:  ctmap.DigitallySigned_ECDSA,
		Signature:     sig,
	}, nil
}

// SignatureVerifier can verify signatures on SCTs and STHs
type SignatureVerifier struct {
	pubKey  crypto.PublicKey
	KeyName string
}

// PublicKeyFromPEM parses a PEM formatted block and returns the public key
// contained within and any remaining unread bytes, or an error.
func PublicKeyFromPEM(b []byte) (crypto.PublicKey, []byte, error) {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil, rest, fmt.Errorf("no PEM block found in %s", string(b))
	}
	k, err := x509.ParsePKIXPublicKey(p.Bytes)
	return k, rest, err
}

func NewSignatureVerifier(pk crypto.PublicKey) (*SignatureVerifier, error) {
	switch pkType := pk.(type) {
	case *ecdsa.PublicKey:
		params := *(pkType.Params())
		if params != *elliptic.P256().Params() {
			return nil, ErrPointNotOnCurve
		}
	default:
		return nil, ErrWrongKeyType
	}

	id, err := KeyName(pk)
	if err != nil {
		return nil, err
	}

	return &SignatureVerifier{
		pubKey:  pk,
		KeyName: id,
	}, nil
}

func (s SignatureVerifier) Verify(data interface{}, sig *ctmap.DigitallySigned) error {
	if sig.HashAlgorithm != ctmap.DigitallySigned_SHA256 {
		return ErrWrongHashAlgo
	}
	if sig.SigAlgorithm != ctmap.DigitallySigned_ECDSA {
		return ErrWrongSignatureAlgo
	}

	j, err := json.Marshal(data)
	if err != nil {
		return err
	}
	hash := objecthash.CommonJSONHash(string(j))

	ecdsaKey, ok := s.pubKey.(*ecdsa.PublicKey)
	if !ok {
		return ErrWrongKeyType
	}
	var ecdsaSig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig.Signature, &ecdsaSig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
	}
	if len(rest) != 0 {
		log.Printf("Garbage following signature")
	}

	if !ecdsa.Verify(ecdsaKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		return ErrVerificaionFailed
	}
	return nil
}
