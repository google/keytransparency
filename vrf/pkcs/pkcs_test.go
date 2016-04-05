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

package pkcs

import (
	"testing"
)

func TestVRF(t *testing.T) {
	k, pk := KeyGen()

	m1 := []byte("data1")
	m2 := []byte("data2")
	m3 := []byte("data2")
	vrf1, proof1 := k.Evaluate(m1)
	vrf2, proof2 := k.Evaluate(m2)
	vrf3, proof3 := k.Evaluate(m3)
	tests := []struct {
		m     []byte
		vrf   [32]byte
		proof []byte
		want  bool
	}{
		{m1, vrf1, proof1, true},
		{m2, vrf2, proof2, true},
		{m3, vrf3, proof3, true},
		{m3, vrf3, proof2, true},
		{m3, vrf3, proof1, false},
	}

	for _, tc := range tests {
		got := pk.Verify(tc.m, tc.vrf[:], tc.proof)
		if got != tc.want {
			t.Errorf("Verify(%v, %v, %v): got %v, want %v", tc.m, tc.vrf, tc.proof, got, tc.want)
		}
	}
}
