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

package fakevrf

import (
	"github.com/gdbelvin/e2e-key-server/vrf"
	"testing"
)

func TestVRF(t *testing.T) {
	m := []byte("data")
	var k vrf.PrivateKey
	var pk vrf.PublicKey
	k, pk = KeyGen()
	vrf, proof := k.Evaluate(m)
	if !pk.Verify(m, vrf[:], proof) {
		t.Errorf("Verify() failed")
	}
}

func TestVrfIsDeterministc(t *testing.T) {
	m := []byte("data")
	var k vrf.PrivateKey
	k, _ = KeyGen()
	vrf1, _ := k.Evaluate(m)
	vrf2, _ := k.Evaluate(m)
	if vrf1 != vrf2 {
		t.Errorf("VRF(%v) = %v != %v", m, vrf1, vrf2)
	}
}
