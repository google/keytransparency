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

// Package vrf defines the interface to a verifiable random function.
package vrf

import (
	"bytes"
	"crypto"
	"encoding/binary"
)

// A VRF is a pseudorandom function f_k from a secret key k, such that that
// knowledge of k not only enables one to evaluate f_k at for any message m,
// but also to provide an NP-proof that the value f_k(m) is indeed correct
// without compromising the unpredictability of f_k for any m' != m.
// http://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=814584

// PrivateKey supports evaluating the VRF function.
type PrivateKey interface {
	// Evaluate returns the output of H(f_k(m)) and its proof.
	Evaluate(m []byte) (index [32]byte, proof []byte)
	// Public returns the corresponding public key.
	Public() crypto.PublicKey
}

// PublicKey supports verifying output from the VRF function.
type PublicKey interface {
	// ProofToHash verifies the NP-proof supplied by Proof and outputs Index.
	ProofToHash(m, proof []byte) (index [32]byte, err error)
}

// UniqueID computes a unique string for a domain, userID and appID combo.
func UniqueID(userID, appID string) []byte {
	b := new(bytes.Buffer)
	binary.Write(b, binary.BigEndian, uint32(len(userID)))
	b.WriteString(userID)
	binary.Write(b, binary.BigEndian, uint32(len(appID)))
	b.WriteString(appID)
	return b.Bytes()
}
