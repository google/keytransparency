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
	"io"
	"log"
	"math/big"

	"github.com/benlaurie/objecthash/go/objecthash"

	"github.com/google/key-transparency/core/proto/ctmap"
)

var (
	// ErrWrongKeyType occurs when a key is not an ECDSA key.
	ErrWrongKeyType = errors.New("not an ECDSA key")
	// ErrPointNotOnCurve occurs when a public key is not on the curve.
	ErrPointNotOnCurve = errors.New("point is not on the P256 curve")
	// ErrWrongHashAlgo occurs when a hash algorithm other than SHA256 was specified.
	ErrWrongHashAlgo = errors.New("not the SHA256 hash algorithm")
	// ErrWrongSignatureAlgo occurs when a signature algorithm other than ECDSA was specified.
	ErrWrongSignatureAlgo = errors.New("not the ECDSA signature algorithm")
	// ErrExtraDataAfterSig occurs when extra data was found after the signature.
	ErrExtraDataAfterSig = errors.New("extra data found after signature")
	// ErrVerificaionFailed occurs when the signature verification failed.
	ErrVerificaionFailed = errors.New("failed to verify ECDSA signature")
)

// Signer generates signatures with a single key.
type Signer struct {
	privKey crypto.PrivateKey
	KeyName string
	rand    io.Reader
}

// GenerateKeyPair creates a new random keypair and returns the wrapped signer and verifier.
func GenerateKeyPair() (*Signer, *Verifier, error) {
	pubkeyCurve := elliptic.P256()
	privatekey := new(ecdsa.PrivateKey)
	privatekey, err := ecdsa.GenerateKey(pubkeyCurve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sig, err := NewSigner(rand.Reader, privatekey)
	if err != nil {
		return nil, nil, err
	}
	ver, err := NewVerifier(privatekey.Public())
	if err != nil {
		return nil, nil, err
	}
	return sig, ver, nil
}

// PrivateKeyFromPEM parses a PEM formatted block and returns the private key
// contained within and any remaining unread bytes, or an error.
func PrivateKeyFromPEM(b []byte) (crypto.Signer, []byte, error) {
	p, rest := pem.Decode(b)
	if p == nil {
		return nil, rest, fmt.Errorf("no PEM block found in %s", string(b))
	}
	k, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return k, rest, nil
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

// NewSigner creates a signer object from a private key.
func NewSigner(rand io.Reader, pk crypto.Signer) (*Signer, error) {
	switch pkType := pk.(type) {
	case *ecdsa.PrivateKey:
		params := *(pkType.Params())
		if params != *elliptic.P256().Params() {
			return nil, ErrPointNotOnCurve
		}
		if !elliptic.P256().IsOnCurve(pkType.X, pkType.Y) {
			return nil, ErrPointNotOnCurve
		}
	default:
		return nil, ErrWrongKeyType
	}

	id, err := KeyName(pk.Public())
	if err != nil {
		return nil, err
	}

	return &Signer{
		privKey: pk,
		KeyName: id,
		rand:    rand,
	}, nil
}

// Sign generates a digital signature object.
func (s Signer) Sign(data interface{}) (*ctmap.DigitallySigned, error) {
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
	ecSig.R, ecSig.S, err = ecdsa.Sign(s.rand, ecdsaKey, hash[:])
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

// Verifier can verify signatures on SCTs and STHs
type Verifier struct {
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
	if err != nil {
		return nil, nil, err
	}
	return k, rest, nil
}

// NewVerifier creates a verifier from a ECDSA public key.
func NewVerifier(pk crypto.PublicKey) (*Verifier, error) {
	switch pkType := pk.(type) {
	case *ecdsa.PublicKey:
		params := *(pkType.Params())
		if params != *elliptic.P256().Params() {
			return nil, ErrPointNotOnCurve
		}
		if !elliptic.P256().IsOnCurve(pkType.X, pkType.Y) {
			return nil, ErrPointNotOnCurve
		}
	default:
		return nil, ErrWrongKeyType
	}

	id, err := KeyName(pk)
	if err != nil {
		return nil, err
	}

	return &Verifier{
		pubKey:  pk,
		KeyName: id,
	}, nil
}

// Verify checks the digital signature associated applied to data.
func (s Verifier) Verify(data interface{}, sig *ctmap.DigitallySigned) error {
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
		return ErrExtraDataAfterSig
	}

	if !ecdsa.Verify(ecdsaKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		return ErrVerificaionFailed
	}
	return nil
}
