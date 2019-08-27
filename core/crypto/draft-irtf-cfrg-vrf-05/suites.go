package vrf

import (
	"crypto"
	"crypto/elliptic"
	"math/big"
)

type ECVRFSuite struct {
	// suite is a single nonzero octet specifying the ECVRF
	// ciphersuite, which determines the options below.
	suite byte
	// E elliptic curve (EC) defined over F
	E    elliptic.Curve
	Hash crypto.Hash
	//nonce func()
	// Int2String converts nonnegative integer a to to octet string of
	// length len as specified in Section 5.5.
	Int2String func(a, l int) []byte
	String2Int func()

	// Point2String converts an EC point to an ptLen-octet string as
	// specified in Section 5.5
	Point2String func(curve elliptic.Curve, x, y *big.Int) []byte

	// String2Point converts an octet string to an EC point
	// according to the encoding specified in Section 5.1.3 of [RFC8032].
	// This function MUST output INVALID if the octet string does not
	// decode to an EC point.
	String2Point func(curve elliptic.Curve, h []byte) (x, y *big.Int, err error)
	// ArbitraryString2Point onverts an arbitrary octet string to an EC
	// point as specified in Section 5.5
	ArbitraryString2Point func(curve elliptic.Curve, h [32]byte) (x, y *big.Int, err error)
	// HashToCurve is a collision resistant hash of strings to an EC point;
	// options described in Section 5.4.1 and specified in Section 5.5.
	// HashToCurveTryAndIncrement takes in the VRF input alpha and converts
	// it to H, an EC point in G.
	HashToCurve func(Y *PublicKey, alpha []byte) (x, y *big.Int)
}

func ECVRF_P256_SHA256_TAI() Interface {
	return &ECVRF{ECVRFSuite{
		suite: 0x01,
		E:     elliptic.P256(),
		Hash:  crypto.SHA256,
		// nonce: // Section 5.4.2.1.
		Int2String: I2OSP, // RFC8017 section-4.1 (big endian representation)
		// string2int: // Section 4.2

		// Point2String converts an EC point to an octet string according to
		// the encoding specified in Section 2.3.3 of [SECG1] with point
		// compression on.  This implies ptLen = 2n + 1 = 33.
		Point2String: SECG1EncodeCompressed, // SECG1 Section 2.3.3

		// String2Point converts an octet string to an EC point
		// according to the encoding specified in Section 2.3.4 of
		// [SECG1].  This function MUST output INVALID if the octet
		// string does not decode to an EC point.
		String2Point: SECG1Decode, // Section 2.3.4 of [SECG1]

		// ArbitraryString2Point (h_string) = string_to_point(0x02
		// || h_string) (where 0x02 is a single octet with value 2,
		// 0x02=int_to_string(2, 1)).  The input h_string is a 32-octet
		// string and the output is either an EC point or "INVALID".
		ArbitraryString2Point: ArbitraryString2Point,        // string_to_point(0x02 || h_string)
		HashToCurve:           v.HashToCurveTryAndIncrement, // Section 5.4.1.1.
	}}
}

// ECVRF returns a Elliptic Curve Verifiable Random Function that satisfies the
// trusted uniqueness, trusted collision resistance, and full pseudorandomness
// properties.
func ECVRF_P256_SHA256_SWU() VRF {
	s := ECVRF{
		suite: 0x02,
		// ECVRF_hash_to_curve: // Section 5.4.1.3
	}
}
