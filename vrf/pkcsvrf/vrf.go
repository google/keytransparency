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

// Package pkcsvrf implements a verifiable random funciton with deterministic pkcsv1.5
package pkcsvrf

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
)

var hashSum = sha256.Sum256
var hashAlgo = crypto.SHA256

type Key rsa.PrivateKey
type PubKey rsa.PublicKey

// KeyGen generates a fresh keypair for this Vrf
func KeyGen() (*Key, *PubKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("GenerateKey failed %v", err)
		return nil, nil
	}
	return (*Key)(priv), (*PubKey)(&priv.PublicKey)
}

// Vrf returns the verifiable unpredictable function evaluated at m.
func (k *Key) Vrf(m []byte) ([32]byte, error) {
	sig, err := k.Proof(m)
	return hashSum(sig), err
}

// Proof returns a pkcs signature prooving that Vrf(m) is correct.
func (k *Key) Proof(m []byte) ([]byte, error) {
	h := hashSum(m)
	sig, err := rsa.SignPKCS1v15(nil, (*rsa.PrivateKey)(k), hashAlgo, h[:])
	if err != nil {
		return make([]byte, 0), err
	}
	return sig, nil
}

// Verify asserts that vrf is the hash of proof and the proof is correct.
func (pk *PubKey) Verify(m, proof []byte, vrf [32]byte) error {
	// Assert vrf == h(proof).
	h := hashSum(proof)
	if h != vrf {
		return rsa.ErrVerification
	}
	// Assert sig(h(m)) is correct.
	h = hashSum(m)
	return rsa.VerifyPKCS1v15((*rsa.PublicKey)(pk), hashAlgo, h[:], proof)
}
