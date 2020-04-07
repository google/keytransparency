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
	"bytes"
	"crypto/elliptic"
	"errors"
	"math/big"
)

// i2osp converts a nonnegative integer to an octet string of a specified length.
// RFC8017 section-4.1 (big endian representation)
func i2osp(x *big.Int, rLen uint) []byte {
	// 1.  If x >= 256^rLen, output "integer too large" and stop.
	upperBound := new(big.Int).Lsh(big.NewInt(1), rLen*8)
	if x.Cmp(upperBound) >= 0 {
		panic("integer too large")
	}
	// 2.  Write the integer x in its unique rLen-digit representation in base 256:
	//     x = x_(rLen-1) 256^(rLen-1) + x_(rLen-2) 256^(rLen-2) + ...  + x_1 256 + x_0,
	//     where 0 <= x_i < 256
	//     (note that one or more leading digits will be zero if x is less than 256^(rLen-1)).
	// 3.  Let the octet X_i have the integer value x_(rLen-i) for 1 <= i <= rLen.
	//     Output the octet string X = X_1 X_2 ... X_rLen.

	var b bytes.Buffer
	xLen := (uint(x.BitLen()) + 7) >> 3
	if rLen > xLen {
		b.Write(make([]byte, rLen-xLen)) // prepend 0s
	}
	b.Write(x.Bytes())
	return b.Bytes()[uint(b.Len())-rLen:] // The rightmost rLen bytes.
}

// SECG1EncodeCompressed converts an EC point to an octet string according to
// the encoding specified in Section 2.3.3 of [SECG1] with point compression
// on. This implies ptLen = 2n + 1 = 33.
//
// SECG1 Section 2.3.3 https://www.secg.org/sec1-v1.99.dif.pdf
//
// (Note that certain software implementations do not introduce a separate
// elliptic curve point type and instead directly treat the EC point as an
// octet string per above encoding.  When using such an implementation, the
// point_to_string function can be treated as the identity function.)
func secg1EncodeCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// This file implements compressed point unmarshaling.  Preferably this
// functionality would be in a standard library.  Code borrowed from:
// https://go-review.googlesource.com/#/c/1883/2/src/crypto/elliptic/elliptic.go

// SECG1Decode decodes a EC point, given as a compressed string.
// If the decoding fails x and y will be nil.
//
// http://www.secg.org/sec1-v2.pdf
// https://tools.ietf.org/html/rfc8032#section-5.1.3
// Section 4.3.6 of ANSI X9.62.

var errInvalidPoint = errors.New("invalid point")

func secg1Decode(curve elliptic.Curve, data []byte) (x, y *big.Int, err error) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return nil, nil, errors.New("unrecognized point encoding")
	}
	if len(data) != 1+byteLen {
		return nil, nil, errors.New("invalid length for curve")
	}

	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	params := curve.Params()
	tx := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y2 := y2(params, tx)
	sqrt := defaultSqrt
	ty := sqrt(y2, params.P)
	if ty == nil {
		return nil, nil, errInvalidPoint // "y^2" is not a square
	}
	var y2c big.Int
	y2c.Mul(ty, ty).Mod(&y2c, params.P)
	if y2c.Cmp(y2) != 0 {
		return nil, nil, errInvalidPoint // sqrt(y2)^2 != y2: invalid point
	}
	if ty.Bit(0) != uint(data[0]&1) {
		ty.Sub(params.P, ty)
	}

	return tx, ty, nil // valid point: return it
}

// Use the curve equation to calculate y² given x.
// only applies to curves of the form y² = x³ - 3x + b.
func y2(curve *elliptic.CurveParams, x *big.Int) *big.Int {
	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	y2 := new(big.Int).Sub(x3, threeX)
	y2.Add(y2, curve.B)
	y2.Mod(y2, curve.P)
	return y2
}

func defaultSqrt(x, p *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(x, p) {
		return nil // x is not a square
	}
	return &r
}
