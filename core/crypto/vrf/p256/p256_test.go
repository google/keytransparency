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
	"encoding/hex"
	"math"
	"testing"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	privKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	pubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`
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
	t.Skip("Too long")
	l := 32
	for i := 0; i < 10000; i++ {
		m := make([]byte, 100)
		if _, err := rand.Read(m); err != nil {
			t.Fatalf("Failed generating random message: %v", err)
		}
		x := H2(m)
		if got := len(x.Bytes()); got < 1 || got > l {
			t.Errorf("len(h2(%v)) = %v, want: 1 <= %v <= %v", m, got, got, l)
		}
	}
}

func TestVRF(t *testing.T) {
	k, pk := GenerateKey()

	m1 := []byte("data1")
	m2 := []byte("data2")
	m3 := []byte("data2")
	index1, proof1 := k.Evaluate(m1)
	index2, proof2 := k.Evaluate(m2)
	index3, proof3 := k.Evaluate(m3)
	for _, tc := range []struct {
		m     []byte
		index [32]byte
		proof []byte
		err   error
	}{
		{m1, index1, proof1, nil},
		{m2, index2, proof2, nil},
		{m3, index3, proof3, nil},
		{m3, index3, proof2, nil},
		{m3, index3, proof1, ErrInvalidVRF},
	} {
		index, err := pk.ProofToHash(tc.m, tc.proof)
		if got, want := err, tc.err; got != want {
			t.Errorf("ProofToIndex(%s, %x): %v, want %v", tc.m, tc.proof, got, want)
		}
		if err != nil {
			continue
		}
		if got, want := index, tc.index; got != want {
			t.Errorf("ProofToInex(%s, %x): %x, want %x", tc.m, tc.proof, got, want)
		}
	}
}

func TestReadFromOpenSSL(t *testing.T) {
	for _, tc := range []struct {
		priv string
		pub  string
	}{
		{privKey, pubKey},
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
		_, proof := signer.Evaluate(m)
		if _, err := verifier.ProofToHash(m, proof); err != nil {
			t.Errorf("Failed verifying VRF proof")
		}
	}
}

func TestRightTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[:len(proof)-1]
		if _, err := pk.ProofToHash(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of proof", i)
		}
	}
}

func TestLeftTruncateProof(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	proofLen := len(proof)
	for i := 0; i < proofLen; i++ {
		proof = proof[1:]
		if _, err := pk.ProofToHash(data, proof); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of proof", i)
		}
	}
}

func TestBitFlip(t *testing.T) {
	k, pk := GenerateKey()

	data := []byte("data")
	_, proof := k.Evaluate(data)
	for i := 0; i < len(proof)*8; i++ {
		// Flip bit in position i.
		if _, err := pk.ProofToHash(data, flipBit(proof, i)); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of vrf", i)
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

func TestVectors(t *testing.T) {
	k, err := NewVRFSignerFromPEM([]byte(privKey))
	if err != nil {
		t.Errorf("NewVRFSigner failure: %v", err)
	}
	pk, err := NewVRFVerifierFromPEM([]byte(pubKey))
	if err != nil {
		t.Errorf("NewVRFSigner failure: %v", err)
	}
	for _, tc := range []struct {
		m     []byte
		index [32]byte
	}{
		{
			m:     []byte("test"),
			index: h2i("1af0a7e3d9a96a71be6257cf4ad1a0ffdec57e9959b2eafc4673a6c31241fc9f"),
		},
		{
			m:     nil,
			index: h2i("2ebac3669807f474f4d49891a1d0b2fba8e966f945ac01cbfffb3bb48627e67d"),
		},
	} {
		index, proof := k.Evaluate(tc.m)
		if got, want := index, tc.index; got != want {
			t.Errorf("Evaluate(%s).Index: %x, want %x", tc.m, got, want)
		}
		index2, err := pk.ProofToHash(tc.m, proof)
		if err != nil {
			t.Errorf("ProofToHash(%s): %v", tc.m, err)
		}
		if got, want := index2, index; got != want {
			t.Errorf("ProofToHash(%s): %x, want %x", tc.m, got, want)
		}
	}
}

func h2i(h string) [32]byte {
	b, err := hex.DecodeString(h)
	if err != nil {
		panic("Invalid hex")
	}
	var i [32]byte
	copy(i[:], b)
	return i
}
