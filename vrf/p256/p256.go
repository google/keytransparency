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

// Package p256 implements a verifiable random function using curve p256.
package p256

// Discrete Log based VRF from Appendix A of CONIKS:
// http://www.jbonneau.com/doc/MBBFF15-coniks.pdf
// based on "Unique Ring Signatures, a Practical Construction"
// http://fc13.ifca.ai/proc/5-1.pdf

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"math/big"
)

var (
	curve  = elliptic.P256()
	params = curve.Params()

	// ErrPointNotOnCurve occurs when a public key is not on the curve.
	ErrPointNotOnCurve = errors.New("point is not on the P256 curve")
	// ErrWrongKeyType occurs when a key is not an ECDSA key.
	ErrWrongKeyType = errors.New("not an ECDSA key")
	// ErrNoPEMFound occurs when attempting to parse a non PEM data structure.
	ErrNoPEMFound = errors.New("no PEM block found")
	// ErrInvalidVRF occurs when the VRF does not validate.
	ErrInvalidVRF = errors.New("invalid VRF proof")
)

// PublicKey holds a public VRF key.
type PublicKey struct {
	*ecdsa.PublicKey
}

// PrivateKey holds a private VRF key.
type PrivateKey struct {
	*ecdsa.PrivateKey
}

// GenerateKey generates a fresh keypair for this VRF
func GenerateKey() (*PrivateKey, *PublicKey) {
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil
	}

	return &PrivateKey{key}, &PublicKey{&key.PublicKey}
}

// H1 hashes m to a curve point
func H1(m []byte) (x, y *big.Int) {
	h := sha512.New()
	var i uint32
	byteLen := (params.BitSize + 7) >> 3
	buf := make([]byte, 4)
	for x == nil && i < 100 {
		// TODO: Use a NIST specified DRBG.
		binary.BigEndian.PutUint32(buf[:], i)
		h.Reset()
		h.Write(buf)
		h.Write(m)
		r := []byte{2} // Set point encoding to "compressed".
		r = h.Sum(r)
		x, y = Unmarshal(curve, r[:byteLen+1])
		i++
	}
	return
}

var one = big.NewInt(1)

// H2 hashes to an integer [1,N-1]
func H2(m []byte) *big.Int {
	// NIST SP 800-90A § A.5.1: Simple discard method.
	byteLen := (params.BitSize + 7) >> 3
	h := sha512.New()
	buf := make([]byte, 4)
	for i := uint32(0); ; i++ {
		// TODO: Use a NIST specified DRBG.
		binary.BigEndian.PutUint32(buf[:], i)
		h.Reset()
		h.Write(buf)
		h.Write(m)
		b := h.Sum(nil)
		k := new(big.Int).SetBytes(b[:byteLen])
		if k.Cmp(new(big.Int).Sub(params.N, one)) == -1 {
			return k.Add(k, one)
		}
	}
}

// Evaluate returns the verifiable unpredictable function evaluated at m
func (k PrivateKey) Evaluate(m []byte) (vrf, proof []byte) {
	// Prover chooses r <-- [1,N-1]
	r, _, _, err := elliptic.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil
	}
	ri := new(big.Int).SetBytes(r)

	// H = H1(m)
	hx, hy := H1(m)

	// G is the base point
	// s = H2(m, [r]G, [r]H)
	gRx, gRy := params.ScalarBaseMult(r)
	hRx, hRy := params.ScalarMult(hx, hy, r)
	var b bytes.Buffer
	b.Write(m)
	b.Write(elliptic.Marshal(curve, gRx, gRy))
	b.Write(elliptic.Marshal(curve, hRx, hRy))
	s := H2(b.Bytes())

	// t = r−s*k mod N
	t := new(big.Int).Sub(ri, new(big.Int).Mul(s, k.D))
	t.Mod(t, params.N)

	// Write s and t to a proof blob. Also write leading zeros before s and t
	// if needed.
	var buf bytes.Buffer
	buf.Write(make([]byte, 32-len(s.Bytes())))
	buf.Write(s.Bytes())
	buf.Write(make([]byte, 32-len(t.Bytes())))
	buf.Write(t.Bytes())

	// VRF_k(m) = [k]H
	vrfx, vrfy := params.ScalarMult(hx, hy, k.D.Bytes())
	return elliptic.Marshal(curve, vrfx, vrfy), buf.Bytes()
}

// Verify asserts that vrf is the hash of proof and the proof is correct
func (pk *PublicKey) Verify(m, vrf, proof []byte) error {
	// verifier checks that s == H2(m, [t]G + [s]([k]G), [t]H1(m) + [s]VRF_k(m))
	vrfx, vrfy := elliptic.Unmarshal(curve, vrf)
	if vrfx == nil {
		return ErrInvalidVRF
	}
	if len(proof) != 64 {
		return ErrInvalidVRF
	}

	// Parse proof into s and t
	s := proof[0:32]
	t := proof[32:64]

	// [t]G + [s]([k]G) = [t+ks]G
	gTx, gTy := params.ScalarBaseMult(t)
	pkSx, pkSy := params.ScalarMult(pk.X, pk.Y, s)
	gTKSx, gTKSy := params.Add(gTx, gTy, pkSx, pkSy)

	// H = H1(m)
	// [t]H + [s]VRF = [t+ks]H
	hx, hy := H1(m)
	hTx, hTy := params.ScalarMult(hx, hy, t)
	vSx, vSy := params.ScalarMult(vrfx, vrfy, s)
	h1TKSx, h1TKSy := params.Add(hTx, hTy, vSx, vSy)

	// H2(m, [t]G + [s]([k]G), [t]H + [s]VRF)
	// = H2(m, [t+ks]G, [t+ks]H)
	// = H2(m, [r]G, [r]H)
	var b bytes.Buffer
	b.Write(m)
	b.Write(elliptic.Marshal(curve, gTKSx, gTKSy))
	b.Write(elliptic.Marshal(curve, h1TKSx, h1TKSy))
	h2 := H2(b.Bytes())

	if !hmac.Equal(s, h2.Bytes()) {
		return ErrInvalidVRF
	}
	return nil
}

// Index computes the index for a given vrf output.
func (k *PrivateKey) Index(vrf []byte) [32]byte {
	return sha256.Sum256(vrf)
}

// Index computes the index for a given vrf output.
func (pk *PublicKey) Index(vrf []byte) [32]byte {
	return sha256.Sum256(vrf)
}

// NewVRFSigner creates a signer object from a private key.
func NewVRFSigner(key *ecdsa.PrivateKey) (*PrivateKey, error) {
	if *(key.Params()) != *curve.Params() {
		return nil, ErrPointNotOnCurve
	}
	return &PrivateKey{key}, nil
}

// NewVRFVerifier creates a verifier object from a public key.
func NewVRFVerifier(pubkey *ecdsa.PublicKey) (*PublicKey, error) {
	if *(pubkey.Params()) != *curve.Params() {
		return nil, ErrPointNotOnCurve
	}
	return &PublicKey{pubkey}, nil
}

// NewVRFSignerFromPEM creates a vrf private key from a PEM data structure.
func NewVRFSignerFromPEM(b []byte) (*PrivateKey, error) {
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, ErrNoPEMFound
	}
	k, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	vrfPriv, err := NewVRFSigner(k)
	if err != nil {
		return nil, err
	}
	return vrfPriv, nil
}
