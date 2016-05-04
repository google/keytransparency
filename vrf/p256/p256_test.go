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

package p256

import (
	"log"
	"testing"
)

func TestH1(t *testing.T) {
	tests := []struct {
		m string
	}{
		{""},
		{"a"},
		{"bbbbbbbbbbbbbbbbbbbbbbb"},
	}
	for _, tc := range tests {
		x, y := H1([]byte(tc.m))
		if x == nil {
			t.Errorf("H1(%v)=%v, want curve point", tc.m, x)
		}
		if got := curve.Params().IsOnCurve(x, y); got != true {
			t.Errorf("H1(%v)=%v, is not on curve", tc.m)
		}
	}
}

func TestH2(t *testing.T) {
	tests := []struct {
		m string
		l int
	}{
		{"", 32},
		{"a", 32},
		{"bbbbbbbbbbbbbbbbbbbbbbb", 32},
	}
	for _, tc := range tests {
		x := H2([]byte(tc.m))
		if got := len(x.Bytes()); got != tc.l {
			t.Errorf("len(h2(%v)) = %v, want %v", tc.m, got, tc.l)
		}
	}
}

func TestVRF(t *testing.T) {
	k, pk := GenerateKey()

	m1 := []byte("data1")
	m2 := []byte("data2")
	m3 := []byte("data2")
	vrf1, proof1 := k.Evaluate(m1)
	vrf2, proof2 := k.Evaluate(m2)
	vrf3, proof3 := k.Evaluate(m3)
	tests := []struct {
		m     []byte
		vrf   []byte
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

func TestSerization(t *testing.T) {
	prvA, pubA := GenerateKey()
	m := []byte("M")
	vrf, proof := prvA.Evaluate(m)
	tests := []struct {
		prv   []byte
		pub   []byte
		want  bool
		m     []byte
		vrf   []byte
		proof []byte
	}{
		{prvA.Bytes(), pubA.Bytes(), true, m, vrf, proof},
	}
	for _, tc := range tests {
		_, err := ParsePrivateKey(tc.prv)
		if err != nil {
			t.Errorf("Failed parseing private key: %v", err)
		}
		log.Printf("AA:%v", tc.pub)
		pub, err := ParsePublicKey(tc.pub)
		if err != nil {
			t.Errorf("Failed parseing public key: %v", err)
		}
		if got := pub.Verify(tc.m, tc.vrf, tc.proof); got != true {
			t.Errorf("Failed verifying VRF proof")
		}
	}
}
