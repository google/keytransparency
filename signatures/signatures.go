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

	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
)

type SignatureSigner struct {
	privKey crypto.PrivateKey
	Name    string
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

// Name is the first 8 hex digits of the SHA256 of the public pem.
func Name(k crypto.PublicKey) (string, error) {
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

	id, err := Name(pk.Public())
	if err != nil {
		return nil, err
	}

	return &SignatureSigner{
		privKey: pk,
		Name:    id,
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
		return nil, fmt.Errorf("cannot verify ECDSA signature with key")
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
	pubKey crypto.PublicKey
	Name   string
}

// PublicKeyFromPEM parses a PEM formatted block and returns the public key contained within and any remaining unread bytes, or an error.
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
			e := fmt.Errorf("public is ECDSA, but not on the P256 curve")
			return nil, e
		}
	default:
		return nil, fmt.Errorf("Unsupported public key type %v", pkType)
	}

	id, err := Name(pk)
	if err != nil {
		return nil, err
	}

	return &SignatureVerifier{
		pubKey: pk,
		Name:   id,
	}, nil
}

func (s SignatureVerifier) Verify(data interface{}, sig *ctmap.DigitallySigned) error {
	if sig.HashAlgorithm != ctmap.DigitallySigned_SHA256 {
		return fmt.Errorf("unsupported HashAlgorithm in signature: %v", sig.HashAlgorithm)
	}
	if sig.SigAlgorithm != ctmap.DigitallySigned_ECDSA {
		return fmt.Errorf("unsupported signature type %v", sig.SigAlgorithm)
	}

	j, err := json.Marshal(data)
	if err != nil {
		return err
	}
	hash := objecthash.CommonJSONHash(string(j))

	ecdsaKey, ok := s.pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("cannot verify ECDSA signature with %T key", s.pubKey)
	}
	var ecdsaSig struct {
		R, S *big.Int
	}
	rest, err := asn1.Unmarshal(sig.Signature, &ecdsaSig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
	}
	if len(rest) != 0 {
		log.Printf("Garbage following signature %v", rest)
	}

	if !ecdsa.Verify(ecdsaKey, hash[:], ecdsaSig.R, ecdsaSig.S) {
		return errors.New("failed to verify ecdsa signature")
	}
	return nil
}
