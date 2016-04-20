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

// Package vrfsha implements a fake verifiable random funciton.
// Note: It does not satisfy the security requiremebts of a VRF.
package fakevrf

import (
	"crypto/sha256"
	"errors"
)

var hashSum = sha256.Sum256

type Key struct{}
type PubKey struct{}

func KeyGen() (*Key, *PubKey) {
	return &Key{}, &PubKey{}
}

// VRF computes a mock verifiable unpredictable function.
func (k *Key) Vrf(m []byte) ([32]byte, error) {
	return hashSum(m), nil
}

// Proof returns nothing for this mock unpredictable function.
func (k *Key) Proof(m []byte) ([]byte, error) {
	return nil, nil
}

// Verify asserts that vrf is the hash of m
func (pk *PubKey) Verify(m, proof []byte, vrf [32]byte) error {
	h := hashSum(m)
	if h != vrf {
		return errors.New("Verification Error")
	}
	return nil
}
