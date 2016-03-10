// Copyright 2015 Google Inc. All Rights Reserved.
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

package vrf25519

import (
	"bytes"
	"testing"
)

var (
	BasePointOrderLE = [32]byte{237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16}
)

// package vrf25519 implements a verifiable random function using EC25519.

func TestLittleEndian(t *testing.T) {
	if got, want := littleEndian(BasePointOrderBE[:]), BasePointOrderLE; got != want {
		t.Errorf("littleEndian(%v)=\n%v, want \n%v", BasePointOrderBE, got, want)
	}
}

func TestBigEndian(t *testing.T) {
	if got, want := bigEndian(BasePointOrderLE), BasePointOrderBE[:]; !bytes.Equal(got, want) {
		t.Errorf("bigEndian(%v)=\n%v, want \n%v", BasePointOrderLE, got, want)
	}
}

func TestVRF(t *testing.T) {
	m := []byte("data")
	k := KeyGen()
	vrf := k.VRF(m)
	c := k.ZKProof(m)
	if !Verify(m, c, k.PublicKey, vrf) {
		t.Errorf("Verify() failed")
	}
}
