package vrf

import (
	"bytes"
	"crypto/elliptic"
	"encoding/binary"
	"math/big"
)

// I2OSP converts a nonnegative integer to an octet string of a specified length.
// RFC8017 section-4.1 (big endian representation)
func I2OSP(x, xLen uint) []byte {
	intLen := uint(4) // Size of uint32
	// 1.  If x >= 256^xLen, output "integer too large" and stop.
	if xLen < intLen && x >= 1<<(xLen*8) {
		panic("integer too large")
	}
	// 2.  Write the integer x in its unique xLen-digit representation in base 256:
	//     x = x_(xLen-1) 256^(xLen-1) + x_(xLen-2) 256^(xLen-2) + ...  + x_1 256 + x_0,
	//     where 0 <= x_i < 256
	//     (note that one or more leading digits will be zero if x is less than 256^(xLen-1)).
	// 3.  Let the octet X_i have the integer value x_(xLen-i) for 1 <= i <= xLen.
	//     Output the octet string X = X_1 X_2 ... X_xLen.

	var b bytes.Buffer
	if xLen > intLen {
		b.Write(make([]byte, xLen-intLen)) // prepend 0s
	}
	if err := binary.Write(&b, binary.BigEndian, uint32(x)); err != nil {
		panic(err)
	}
	return b.Bytes()[uint(b.Len())-xLen:] // The rightmost xLen bytes.
}

// func String2Int(a []byte) int {}

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
func SECG1EncodeCompressed(curve elliptic.Curve, x, y *big.Int) []byte {
	byteLen := (curve.Params().BitSize + 7) >> 3
	ret := make([]byte, 1+byteLen)
	ret[0] = 2 // compressed point

	xBytes := x.Bytes()
	copy(ret[1+byteLen-len(xBytes):], xBytes)
	ret[0] += byte(y.Bit(0))
	return ret
}

// SECG1Decode decodes a point, given as a 32-octet string.
//
// https://tools.ietf.org/html/rfc8032#section-5.1.3
func SECG1Decode(curve elliptic.Curve, h []byte) (x, y *big.Int) {
	x, y = Unmarshal(curve, h)
	return
}

// ArbitraryString2Point returns string_to_point(0x02 || h_string)
// Attempts to interpret an arbitrary string as a compressed elliptic code point.
// The input h is a 32-octet string.  Returns either an EC point or "INVALID".
func ArbitraryString2Point(curve elliptic.Curve, h []byte) (x, y *big.Int) {
	var b bytes.Buffer
	b.Write([]byte{0x02})
	b.Write(h[:])
	return SECG1Decode(curve, b.Bytes())
}
