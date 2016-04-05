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

// Package pkcsvrf implements a verifiable unpredicatble funciton with deterministic pkcsv1.5
package pkcs

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"log"
)

type PrivateKey rsa.PrivateKey
type PublicKey rsa.PublicKey

// GenerateKey generates a fresh keypair for this VRF
func GenerateKey() (*PrivateKey, *PublicKey) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("GenerateKey failed %v", err)
		return nil, nil
	}
	return (*PrivateKey)(priv), (*PublicKey)(&priv.PublicKey)
}

// Evaluate returns the verifiable unpredictable function evaluated at m.
func (k *PrivateKey) Evaluate(m []byte) (vrf [32]byte, proof []byte) {
	h := sha256.Sum256(m)
	sig, err := rsa.SignPKCS1v15(nil, (*rsa.PrivateKey)(k), crypto.SHA256, h[:])
	if err != nil {
		log.Fatalf("Failed SignPKCS1v15: %v", err)
	}

	vrf = sha256.Sum256(sig)
	proof = sig
	return
}

// Verify asserts that vrf is the hash of proof and the proof is correct.
func (pk *PublicKey) Verify(m, vrf, proof []byte) bool {
	// Assert vrf == h(proof).
	var v [32]byte
	copy(v[:], vrf)
	h := sha256.Sum256(proof)
	if len(vrf) != 32 || h != v {
		return false
	}
	// Assert sig(h(m)) is correct.
	h = sha256.Sum256(m)
	return nil == rsa.VerifyPKCS1v15((*rsa.PublicKey)(pk), crypto.SHA256, h[:], proof)
}
