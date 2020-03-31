package vrf

import (
	"crypto"
	"crypto/elliptic"
	"math/big"

	_ "crypto/sha256"
)

// Conversions between types
type Conversions struct {
	// Int2String converts nonnegative integer a to to octet string of
	// length len as specified in Section 5.5.
	Int2String func(a, l uint) []byte

	// String2Int converts an octet string a_string to a nonnegative
	// integer as specified in Section 5.5.
	String2Int func(a []byte) uint

	// Point2String converts an EC point to an ptLen-octet string as
	// specified in Section 5.5
	Point2String func(curve elliptic.Curve, x, y *big.Int) []byte

	// String2Point converts an octet string to an EC point
	// according to the encoding specified in Section 5.1.3 of [RFC8032].
	// This function MUST output INVALID if the octet string does not
	// decode to an EC point.
	String2Point func(curve elliptic.Curve, h []byte) (x, y *big.Int)

	// ArbitraryString2Point converts an arbitrary octet string to an EC
	// point as specified in Section 5.5
	ArbitraryString2Point func(curve elliptic.Curve, h []byte) (x, y *big.Int)
}

type ECVRFSuite struct {
	EC elliptic.Curve // elliptic curve defined over F which fixes
	//   F - finite field
	n     int // 2n - length, in octets, of a field element in F, rounded up to the nearest even integer
	ptLen int // length, in octets, of an EC point encoded as an octet string
	//   G - subgroup of E of large prime order
	//   q - prime order of group G
	//       q = EC.Params().N
	qLen int // length of q in octets, i.e., smallest integer such that
	//   2^(8qLen)>q (note that in the typical case, qLen equals 2n or is
	//   close to 2n)
	//

	cofactor int //number of points on E divided by q

	//   B - generator of group G
	// suite is a single nonzero octet specifying the ECVRF
	// ciphersuite, which determines the options below.
	SuiteString   []byte
	Hash          crypto.Hash
	Conversions   // Type conversions
	GenerateNonce func(hash crypto.Hash, SK *PrivateKey, h []byte) (k *big.Int)
	// HashToCurve is a collision resistant hash of strings to an EC point;
	// options described in Section 5.4.1 and specified in Section 5.5.
	// HashToCurveTryAndIncrement takes in the VRF input alpha and converts
	// it to H, an EC point in G.
	HashToCurve func(v *ECVRFSuite, Y *PublicKey, alpha []byte) (x, y *big.Int)
}

// ECVRF_P256_SHA256_TAI returns a elliptic curve based VRF instantiated with
// P256, SHA256, and the "Try And Increment" strategy for hashing to the curve.
func ECVRF_P256_SHA256_TAI() *ECVRF {
	return &ECVRF{ECVRFSuite{
		SuiteString: []byte{0x01}, // int_to_string(1, 1)
		// E group G is the NIST P-256 elliptic curve, with curve
		// parameters as specified in [FIPS-186-4] (Section D.1.2.3)
		// and [RFC5114] (Section 2.6).
		EC: elliptic.P256(),
		// For this group, 2n = qLen = 32 and cofactor = 1.
		n:        16, // EC.Params().BitSize / 8 / 2
		qLen:     32, // (v.EC.Params().N.BitLen() + 7) / 8
		cofactor: 1,
		ptLen:    33,
		// Hash
		//    hLen - output length in octets of Hash; must be at least 2n
		Hash: crypto.SHA256,
		Conversions: Conversions{
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

			// ArbitraryString2Point returns string_to_point(0x02 || h_string)
			ArbitraryString2Point: ArbitraryString2Point,
		},
		HashToCurve:   HashToCurveTAI,       // Section 5.4.1.1.
		GenerateNonce: GenerateNonceRFC6979, // Section 5.4.2.1.
	}}
}

// ECVRF returns a Elliptic Curve Verifiable Random Function that satisfies the
// trusted uniqueness, trusted collision resistance, and full pseudorandomness
// properties.
/*
func ECVRF_P256_SHA256_SWU() VRF {
	s := ECVRF{
		suite: 0x02,
		// ECVRF_hash_to_curve: // Section 5.4.1.3
	}
}
*/
