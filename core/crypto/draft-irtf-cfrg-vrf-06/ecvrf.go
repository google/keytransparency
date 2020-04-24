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

package vrf

import (
	"crypto"
	"crypto/elliptic"
	"math/big"
)

// PublicKey holds a public VRF key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey holds a private VRF key.
type PrivateKey struct {
	PublicKey
	x *big.Int
}

// Public returns the public key corresponding to priv.
func (priv *PrivateKey) Public() *PublicKey {
	return &priv.PublicKey
}

func NewKey(curve elliptic.Curve, sk []byte) *PrivateKey {
	Yx, Yy := curve.ScalarBaseMult(sk)
	return &PrivateKey{
		x:         new(big.Int).SetBytes(sk),             // Use SK to derive the VRF secret scalar x
		PublicKey: PublicKey{Curve: curve, X: Yx, Y: Yy}, // VRF public key Y = x*B
	}
}

// ECVRFParams holds shared values across ECVRF implementations.
// ECVRFParams also has generic algorithms that rely on ECVRFAux for specific sub algorithms.
type ECVRFParams struct {
	suiteString []byte         // single nonzero octet specifying the ECVRF ciphersuite
	ec          elliptic.Curve // Elliptic curve defined over F
	//   G - subgroup of E of large prime order.
	//   q - prime order of group G, ec.Params().N
	//   B - generator of group G, ec.Params.{Gx,Gy}
	n        int  // 2n  - length, in octets, of a field element in F.
	ptLen    int  // length, in octets, of an EC point encoded as an octet string
	qLen     int  // length of q in octets. (note that in the typical case, qLen equals 2n or is close to 2n)
	cofactor byte //number of points on E divided by q
	hash     crypto.Hash
	aux      ECVRFAux // Auxiliary functions
}

// ECVRFAux contains auxiliary functions nessesary for the computation of ECVRF.
type ECVRFAux interface {
	// PointToString converts an EC point to an octet string according to
	// the encoding specified in Section 2.3.3 of [SECG1] with point
	// compression on.  This implies ptLen = 2n + 1 = 33.
	PointToString(Px, Py *big.Int) []byte

	// StringToPoint converts an octet string to an EC point
	// This function MUST output INVALID if the octet string does not
	// decode to an EC point.
	StringToPoint(h []byte) (Px, Py *big.Int, err error)

	// ArbitraryStringToPoint(s) = string_to_point(0x02 || s)
	// (where 0x02 is a single octet with value 2, 0x02=int_to_string(2, 1)).
	// The input s is a 32-octet string and the output is either an EC point or "INVALID".
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)
}
