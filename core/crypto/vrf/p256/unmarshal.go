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

// This file implements compressed point unmarshaling.  Preferably this
// functionality would be in a standard library.  Code borrowed from:
// https://go-review.googlesource.com/#/c/1883/2/src/crypto/elliptic/elliptic.go

import (
	"crypto/elliptic"
	"math/big"
)

// Unmarshal a compressed point in the form specified in section 4.3.6 of ANSI X9.62.
func Unmarshal(curve elliptic.Curve, data []byte) (x, y *big.Int) {
	byteLen := (curve.Params().BitSize + 7) >> 3
	if (data[0] &^ 1) != 2 {
		return // unrecognized point encoding
	}
	if len(data) != 1+byteLen {
		return
	}

	// Based on Routine 2.2.4 in NIST Mathematical routines paper
	params := curve.Params()
	tx := new(big.Int).SetBytes(data[1 : 1+byteLen])
	y2 := y2(params, tx)
	sqrt := defaultSqrt
	ty := sqrt(y2, params.P)
	if ty == nil {
		return // "y^2" is not a square: invalid point
	}
	var y2c big.Int
	y2c.Mul(ty, ty).Mod(&y2c, params.P)
	if y2c.Cmp(y2) != 0 {
		return // sqrt(y2)^2 != y2: invalid point
	}
	if ty.Bit(0) != uint(data[0]&1) {
		ty.Sub(params.P, ty)
	}

	x, y = tx, ty // valid point: return it
	return
}

// Use the curve equation to calculate y² given x.
// only applies to curves of the form y² = x³ - 3x + b.
func y2(curve *elliptic.CurveParams, x *big.Int) *big.Int {

	// y² = x³ - 3x + b
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)

	threeX := new(big.Int).Lsh(x, 1)
	threeX.Add(threeX, x)

	x3.Sub(x3, threeX)
	x3.Add(x3, curve.B)
	x3.Mod(x3, curve.P)
	return x3
}

func defaultSqrt(x, p *big.Int) *big.Int {
	var r big.Int
	if nil == r.ModSqrt(x, p) {
		return nil // x is not a square
	}
	return &r
}
