package vrf

import (
	"crypto/elliptic"
)

// PublicKey holds a public VRF key.
type PublicKey struct {
	*ecdsa.PublicKey
}

// PrivateKey holds a private VRF key.
type PrivateKey struct {
	*ecdsa.PrivateKey
}

type ECVRF struct {
	// E - elliptic curve (EC) defined over F
	// F - finite field
	// 2n - length, in octets, of a field element in F, rounded up to the
	// nearest even integer
	E elliptic.Curve

	// ptLen - length, in octets, of an EC point encoded as an octet string

	// G - subgroup of E of large prime order

	// q - prime order of group G

	// qLen - length of q in octets, i.e., smallest integer such that
	// 2^(8qLen)>q (note that in the typical case, qLen equals 2n or is
	// close to 2n)

	// cofactor - number of points on E divided by q

	// B - generator of group G

	// Hash - cryptographic hash function
	Hash hash.Hash

	// hLen - output length in octets of Hash; must be at least 2n

	// suite is a single nonzero octet specifying the ECVRF
	// ciphersuite, which determines the above options
	suite byte

	//  Elliptic curve operations are written in additive notation, with
	// P+Q denoting point addition and x*P denoting scalar multiplication
	// of a point P by a scalar x
	// x^y - a raised to the power b
	// x*y - a multiplied by b
	// || - octet string concatenation

	// HashToCurve is a collision resistant hash of strings to an EC point;
	// options described in Section 5.4.1 and specified in Section 5.5.
	HashToCurve func(suite byte, Y, alpha []byte)

	// ECVRF_nonce_generation - derives a pseudorandom nonce from SK and
	// the input as part of ECVRF proving.  Specified in Section 5.5

	// ECVRF_hash_points - collision resistant hash of EC points to an
	// integer.  Specified in Section 5.4.3.
	//
	//     int_to_string(a, len) - conversion of nonnegative integer a to to
	// octet string of length len as specified in Section 5.5.

	// string_to_int(a_string) - conversion of an octet string a_string
	// to a nonnegative integer as specified in Section 5.5.

	// point_to_string - conversion of EC point to an ptLen-octet string
	// as specified in Section 5.5

	// string_to_point - conversion of an ptLen-octet string to EC point
	// as specified in Section 5.5.  string_to_point returns INVALID if
	// the octet string does not convert to a valid EC point.

	// arbitrary_string_to_point - conversion of an arbitrary octet
	// string to an EC point as specified in Section 5.5
}

// Proof returns proof pi that beta is the correct hash output.
// SK - VRF private key
// alpha - input alpha, an octet string
// Returns pi - VRF proof, octet string of length ptLen+n+qLen
func (v *ECVRF) Prove(SK PrivateKey, alpha string) []byte {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	x := SK.D
	PK := SK.Public()

	// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	H := v.HashToCurve(v.suite, Y, alpha)

	// 3.  h_string = point_to_string(H)

	// 4.  Gamma = x*H

	// 5.  k = ECVRF_nonce_generation(SK, h_string)

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)

	// 7.  s = (k + c*x) mod q

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) ||
	//     int_to_string(s, qLen)
}
