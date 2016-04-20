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

// package p256 implements a verifiable random function using curve p256.
package p256

import (
	"bytes"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"math/big"
)

var (
	curve  = elliptic.P256()
	params = curve.Params()
)

type PublicKey struct {
	x *big.Int
	y *big.Int
}
type PrivateKey []byte

// GenerateKey generates a fresh keypair for this VRF
func GenerateKey() (*PrivateKey, *PublicKey) {
	var pub PublicKey
	var priv PrivateKey
	var err error
	priv, pub.x, pub.y, err = elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil
	}
	return (*PrivateKey)(&priv), (*PublicKey)(&pub)
}

// H1 hashes m to a curve point
func H1(m []byte) (x, y *big.Int) {
	h := sha512.New()
	var i uint32
	byteLen := (params.BitSize + 7) >> 3
	buf := make([]byte, 4)
	for x == nil && i < 100 {
		// Hash(i||m) and try to interpret as a compressed point.
		binary.BigEndian.PutUint32(buf[:], i)
		h.Write(buf)
		h.Write(m)
		r := h.Sum(nil)
		r[0] = 2 // Set point encoding to "compressed".
		x, y = Unmarshal(curve, r[:byteLen+1])
		i++
		h.Reset()
	}
	return
}

var one = new(big.Int).SetInt64(1)

// H2 hashes to an integer [1,q]
func H2(m []byte) *big.Int {
	// In this method, 64 more bits are requested from the RBG than are needed
	// for k so that bias produced by the modular reduction is negligible.
	// https://www.nsa.gov/ia/_files/ecdsa.pdf A.2.1.
	h := sha512.New()
	h.Write(m)
	b := h.Sum(nil)
	bLen := params.BitSize/8 + 8
	k := new(big.Int).SetBytes(b[:bLen])
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return k
}

// Evaluate returns the verifiable unpredictable function evaluated at m
func (k PrivateKey) Evaluate(m []byte) (vrf, proof []byte) {
	// Prover chooses r← [1,q]
	r, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil
	}
	ri := new(big.Int).SetBytes(r)

	// h = H1(m)
	hx, hy := H1(m)

	// s = H2(m, g^r, h^r)
	gRx, gRy := params.ScalarBaseMult(r)
	hRx, hRy := params.ScalarMult(hx, hy, r)
	var b bytes.Buffer
	b.Write(m)
	b.Write(elliptic.Marshal(curve, gRx, gRy))
	b.Write(elliptic.Marshal(curve, hRx, hRy))
	s := H2(b.Bytes())

	// t = r−s*k mod q
	ki := new(big.Int).SetBytes(k)
	t := new(big.Int).Sub(ri, new(big.Int).Mul(s, ki))
	t.Mod(t, params.N)

	//Write s,t as proof blob.
	var buf bytes.Buffer
	buf.Write(s.Bytes())
	buf.Write(t.Bytes())

	// VRF_k(m) = H1(m)^k
	vrfx, vrfy := params.ScalarMult(hx, hy, k)
	return elliptic.Marshal(curve, vrfx, vrfy), buf.Bytes()
}

// Verify asserts that vrf is the hash of proof and the proof is correct
func (pk *PublicKey) Verify(m, vrf, proof []byte) bool {
	// verifier checks that s == H2(m, g^t * (g^k)^s, H1(m)^t * VRF_k(m)^s)
	vrfx, vrfy := elliptic.Unmarshal(curve, vrf)
	if vrfx == nil {
		return false
	}

	// Parse proof into s and t
	s := proof[0:32]
	t := proof[32:64]

	// g^t * (g^k)^s = g^(t+ks)
	gTx, gTy := params.ScalarBaseMult(t)
	gSx, gSy := params.ScalarMult(pk.x, pk.y, s)
	gTKSx, gTKSy := params.Add(gTx, gTy, gSx, gSy)

	// H1(m)^t * vrf^s = h^(t+ks)
	hx, hy := H1(m)
	hTx, hTy := params.ScalarMult(hx, hy, t)
	vSx, vSy := params.ScalarMult(vrfx, vrfy, s)
	h1TKSx, h1TKSy := params.Add(hTx, hTy, vSx, vSy)

	// H2(m, g^t * (g^k)^s, H1(m)^t * VRF_k(m)^s)
	// = H2(m, g^(t+ks), h^(t+ks)
	// = H2(m, g^r, h^r)
	var b bytes.Buffer
	b.Write(m)
	b.Write(elliptic.Marshal(curve, gTKSx, gTKSy))
	b.Write(elliptic.Marshal(curve, h1TKSx, h1TKSy))
	h2 := H2(b.Bytes())

	return hmac.Equal(s, h2.Bytes())
}
