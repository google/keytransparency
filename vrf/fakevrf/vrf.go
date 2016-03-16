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
)

var hashSum = sha256.Sum256

type Key struct{}
type PubKey struct{}

func KeyGen() (*Key, *PubKey) {
	return &Key{}, &PubKey{}
}

// Evaluate computes a mock verifiable unpredictable function.
func (k *Key) Evaluate(m []byte) (vrf [32]byte, proof []byte) {
	return hashSum(m), nil
}

// Verify asserts that vrf is the hash of m
func (pk *PubKey) Verify(m, vrf, proof []byte) bool {
	var v [32]byte
	copy(v[:], vrf)
	return len(vrf) == 32 && v == hashSum(m)
}
