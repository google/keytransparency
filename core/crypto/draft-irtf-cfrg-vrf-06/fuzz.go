// Copyright 2020 Google Inc. All Rights Reserved.
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

// +build gofuzz

package vrf

// To run the fuzzer:
// $ go get -u github.com/dvyukov/go-fuzz/go-fuzz github.com/dvyukov/go-fuzz/go-fuzz-build
// $ cd core/crypto/draft-irtf-cfrg-vrf-06
// $ go-fuzz-build
// $ go-fuzz

var (
	v     = ECVRFP256SHA256TAI()
	p     = v.Params()
	piLen = p.ptLen + p.n + p.qLen
	skLen = 32
)

// Fuzz returns 1 if the fuzzer should increase the priority of the input,
// -1 if the input must not be added to the corpus, and 0 otherwise.
func FuzzVerify(data []byte) int {
	if len(data) <= skLen+piLen {
		return -1
	}
	sk := NewKey(v.Params().ec, data[:skLen])
	pi := data[skLen : skLen+piLen]
	alpha := data[:skLen+piLen]

	_, err := v.Verify(sk.Public(), pi, alpha)
	if err != nil {
		return 0
	}
	return 1
}

func FuzzProve(data []byte) int {
	if len(data) <= skLen {
		return -1
	}
	sk := NewKey(v.Params().ec, data[:skLen])
	alpha := data[:skLen]

	if _, err := v.ProofToHash(v.Prove(sk, alpha)); err != nil {
		panic(err)
	}
	return 1
}
