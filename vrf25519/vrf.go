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

// package vrf25519 implements a verifiable random function using EC25519.
package vrf25519

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"golang.org/x/crypto/curve25519"
	"log"
	"math/big"
)

var hashSum = sha512.Sum512_256
var BasePointOrderBE = [32]byte{16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 222, 249, 222, 162, 247, 156, 214, 88, 18, 99, 26, 92, 245, 211, 237}

type Key struct {
	privateKey [32]byte // Little endian
	PublicKey  [32]byte // Little endian
}

func New(privateKey [32]byte) *Key {
	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)
	return &Key{privateKey, publicKey}
}

// KeyGen: New EC25519 Key
func KeyGen() *Key {
	var k [32]byte
	randBytes(k[:])
	return New(k)
}

func randBytes(buf []byte) {
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
}

// VRF_k(m) = H1(m)^k
func (k *Key) VRF(m []byte) [32]byte {
	h1 := H1(m)
	var vrf [32]byte
	curve25519.ScalarMult(&vrf, &k.privateKey, &h1)
	return vrf // Little endian
}

// H1 hashes to a public key.  EC25519 defines all 32 bit strings as valid
// public keys. Public keys are not guarunteed to be valid curve points, but
// should be ok to use - as in they don't leak information?
func H1(m []byte) [32]byte {
	return hashSum(m) // Little endian.
}

// H2 hashes to a private key.
// In muliplicative notation, private keys are integers (1,q).
// In EC25519, private keys have certain bits set and cleared to ensure that pub^priv
// does not leak the private key.
func H2(m []byte) [32]byte {
	e := hashSum(m)
	makePrivateKey(&e)
	return e // Little endian
}

// ZKProof shows in zero-knowledge that there is some x for which G = g^k and
// H = h^k for h = H1(m).
func (k *Key) ZKProof(m []byte) []byte {
	// q = 252 + 27742317777372353535851937790883648493.
	// The prover chooses r← (1,q)
	var r [32]byte
	makePrivateKey(&r)
	randBytes(r[:]) // r will act as a private key.
	// Note that this is distinct from being mod q.

	// Unlike multiplicative groups, not every integer mod q is an element
	// of the group.

	// h = H1(m)
	h := H1(m)

	// s = H2(m, g^r, h^r)
	var gR, hR [32]byte
	curve25519.ScalarBaseMult(&gR, &r)
	curve25519.ScalarMult(&hR, &r, &h)
	var b bytes.Buffer
	b.Write(m)
	b.Write(gR[:])
	b.Write(hR[:])
	s := H2(b.Bytes())

	// t = r−s*k mod q
	var ti, ri, si, ki, qi big.Int
	ri.SetBytes(bigEndian(r))
	si.SetBytes(bigEndian(s))
	ki.SetBytes(bigEndian(k.privateKey))
	qi.SetBytes(BasePointOrderBE[:])
	ti.Sub(&ri, si.Mul(&si, &ki))
	ti.Mod(&ti, &qi)
	t := littleEndian(ti.Bytes())
	makePrivateKey(&t) // Set bits rather than mod q.

	//Write s,t as proof blob.
	var proof bytes.Buffer
	proof.Write(s[:]) // Little endian.
	proof.Write(t[:]) // Little endian.
	return proof.Bytes()
}

// Verify that VRF_k(m) == H1(m)^k
func Verify(m, proof []byte, G, vrf [32]byte) bool {
	// verifier checks that s == H2(m, g^t * G^s, H1(m)^t * VRF_k(m)^s)

	// Parse proof into s and t
	var s, t [32]byte
	copy(s[:], proof[0:32])
	copy(t[:], proof[32:64])

	// g^t * G^s
	var gT, GS [32]byte
	curve25519.ScalarBaseMult(&gT, &t)
	curve25519.ScalarMult(&GS, &G, &s)
	var gTi, GSi, gTGSi big.Int
	gTi.SetBytes(bigEndian(gT))
	GSi.SetBytes(bigEndian(GS))
	gTGSi.Mul(&gTi, &GSi)
	log.Printf("Sign(ti)=%v", gTGSi.Sign())
	log.Printf("Bytes(ti)=%v", gTGSi.Bytes())
	gTGS := littleEndian(gTGSi.Bytes())

	// H1(m)^t * vrf^s
	h1 := H1(m)
	var h1t, vrfs [32]byte
	curve25519.ScalarMult(&h1t, &t, &h1)
	curve25519.ScalarMult(&vrfs, &s, &vrf)
	var h1ti, vrfsi, h1tvrfsi big.Int
	h1ti.SetBytes(bigEndian(h1t))
	vrfsi.SetBytes(bigEndian(vrfs))
	h1tvrfsi.Mul(&h1ti, &vrfsi)
	h1tvrfs := littleEndian(h1tvrfsi.Bytes())

	//H2(m, g^t * G^s, H1(m)^t * VRF_k(m)^s)
	var b bytes.Buffer
	b.Write(m)
	b.Write(gTGS[:])
	b.Write(h1tvrfs[:])
	h2 := H2(b.Bytes())

	return hmac.Equal(s[:], h2[:])
}

//bigEndian returns the big Endian byte string of a little ending byte string
func bigEndian(le [32]byte) []byte {
	be := make([]byte, 32)
	for i, v := range le {
		be[31-i] = v
	}
	return be
}

func littleEndian(be []byte) [32]byte {
	if len(be) != 32 {
		log.Panicf("len(be)=%v, want 32", len(be))
	}
	var le [32]byte
	for i, v := range be {
		le[31-i] = v
	}
	return le

}

func makePrivateKey(e *[32]byte) {
	e[0] &= 248
	e[31] &= 127
	e[31] |= 64
}
