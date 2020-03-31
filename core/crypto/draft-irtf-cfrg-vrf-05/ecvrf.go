package vrf

import (
	"bytes"
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

func (v *ECVRF) NewKey(curve elliptic.Curve, SK []byte) *PrivateKey {
	Yx, Yy := v.EC.ScalarBaseMult(SK)
	return &PrivateKey{
		x:         new(big.Int).SetBytes(SK),             // Use SK to derive the VRF secret scalar x
		PublicKey: PublicKey{Curve: curve, X: Yx, Y: Yy}, // VRF public key Y = x*B
	}
}

type ECVRF struct {
	ECVRFSuite

	//  Elliptic curve operations are written in additive notation, with
	// P+Q denoting point addition and x*P denoting scalar multiplication
	// of a point P by a scalar x
	// x^y - a raised to the power b
	// x*y - a multiplied by b
	// || - octet string concatenation

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
func (v *ECVRF) Prove(sk *PrivateKey, alpha []byte) []byte {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	x := sk.x
	pk := sk.Public()

	// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy, _ := HashToCurveTryAndIncrement(&v.ECVRFSuite, pk, alpha)

	// 3.  h_string = point_to_string(H)
	hString := v.Point2String(v.EC, Hx, Hy)

	// 4.  Gamma = x*H
	Gx, Gy := v.EC.ScalarMult(Hx, Hy, x.Bytes())

	// 5.  k = ECVRF_nonce_generation(SK, h_string)
	k := v.GenerateNonce(v.Hash, sk, hString)

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)
	Ux, Uy := v.EC.ScalarBaseMult(k.Bytes())
	Vx, Vy := v.EC.ScalarMult(Hx, Hy, k.Bytes())
	c := v.ECVRFHashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 7.  s = (k + c*x) mod q
	s1 := new(big.Int).Mul(c, x)
	s2 := new(big.Int).Add(k, s1)
	s := new(big.Int).Mod(s2, v.EC.Params().N)

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
	pi := new(bytes.Buffer)
	pi.Write(v.Point2String(v.EC, Gx, Gy))
	pi.Write(c.Bytes())
	pi.Write(s.Bytes())

	return pi.Bytes()
}
