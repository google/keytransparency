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
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

func TestH1(t *testing.T) {
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x, y := H1(m)
		if x == nil {
			t.Errorf("H1(%v)=%v, want curve point", m, x)
		}
		if got := curve.Params().IsOnCurve(x, y); !got {
			t.Errorf("H1(%v)=[%v, %v], is not on curve", m, x, y)
		}
	}
}

func TestH2(t *testing.T) {
	l := 32
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x := H2(m)
		if got := len(x.Bytes()); got < 1 && got > l {
			t.Errorf("len(h2(%v)) = %v, want %v", m, got, l)
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
	for _, tc := range []struct {
		m     []byte
		vrf   []byte
		proof []byte
		err   error
	}{
		{m1, vrf1, proof1, nil},
		{m2, vrf2, proof2, nil},
		{m3, vrf3, proof3, nil},
		{m3, vrf3, proof2, nil},
		{m3, vrf3, proof1, ErrInvalidVRF},
	} {
		if got, want := pk.Verify(tc.m, tc.vrf[:], tc.proof), tc.err; got != want {
			t.Errorf("Verify(%v, %v, %v): got %v, want %v", tc.m, tc.vrf, tc.proof, got, want)
		}
	}
}

func TestReadFromOpenSSL(t *testing.T) {
	for _, tc := range []struct {
		priv string
		pub  string
	}{
		{
			// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
			`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`,
			// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
			`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`},
	} {
		// Private VRF Key
		signer, err := NewVRFSignerFromPEM([]byte(tc.priv))
		if err != nil {
			t.Errorf("NewVRFSigner failure: %v", err)
		}

		// Public VRF key
		verifier, err := NewVRFVerifierFromPEM([]byte(tc.pub))
		if err != nil {
			t.Errorf("NewVRFSigner failure: %v", err)
		}

		// Evaluate and verify.
		m := []byte("M")
		vrf, proof := signer.Evaluate(m)
		if verifier.Verify(m, vrf, proof) != nil {
			t.Errorf("Failed verifying VRF proof")
		}
	}
}

func TestRightTruncateVRF(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	vrfLen := len(vrf)
	for i := 0; i < vrfLen; i++ {
		vrf = vrf[:len(vrf)-1]
		if err := pk.Verify(data, vrf, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of vrf", i)
		}
	}
}

func TestLeftTruncateVRF(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	vrfLen := len(vrf)
	for i := 0; i < vrfLen; i++ {
		vrf = vrf[1:]
		if err := pk.Verify(data, vrf, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of vrf", i)
		}
	}
}

func TestRightTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[:len(proof)-1]
		if err := pk.Verify(data, vrf, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of proof", i)
		}
	}
}

func TestLeftTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[1:]
		if err := pk.Verify(data, vrf, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of proof", i)
		}
	}
}

func TestBitFlipVRF(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	for i := 0; i < len(vrf)*8; i++ {
		// Flip bit in position i.
		flippedVrf := flipBit(vrf, i)

		if err := pk.Verify(data, flippedVrf, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of vrf", i)
		}
	}
}

func TestBitFlipProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	vrf, proof := k.Evaluate(data)
	for i := 0; i < len(proof)*8; i++ {
		// Flip bit in position i.
		flippedProof := flipBit(proof, i)

		if err := pk.Verify(data, vrf, flippedProof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of proof", i)
		}
	}
}

func flipBit(a []byte, pos int) []byte {
	index := int(math.Floor(float64(pos) / 8))
	b := byte(a[index])
	b ^= (1 << uint(math.Mod(float64(pos), 8.0)))

	var buf bytes.Buffer
	buf.Write(a[:index])
	buf.Write([]byte{b})
	buf.Write(a[index+1:])
	return buf.Bytes()
}
