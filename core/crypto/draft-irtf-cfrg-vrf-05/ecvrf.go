package vrf

import (
	"bytes"
	"crypto/elliptic"
	"errors"
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
	Hx, Hy, _ := HashToCurveTryAndIncrement(v, v.SuiteString, pk, alpha)

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
	pi.Write(v.Point2String(v.EC, Gx, Gy)) // ptLen
	pi.Write(c.Bytes())                    // n
	pi.Write(s.Bytes())                    // qLen

	return pi.Bytes()
}

// Proof2Hash returns beta
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.2
//
//   Input:
//      pi_string - VRF proof, octet string of length ptLen+n+qLen
//
//   Output:
//      "INVALID", or
//      beta_string - VRF hash output, octet string of length hLen
//
//   Important note:
//      ECVRF_proof_to_hash should be run only on pi_string that is known
//      to have been produced by ECVRF_prove, or from within ECVRF_verify
//      as specified in Section 5.3.
func (v *ECVRF) Proof2Hash(pi []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode_proof(pi_string)
	Gx, Gy, _, _, err := v.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}
	// 3.  (Gamma, c, s) = D

	// 4.  three_string = 0x03 = int_to_string(3, 1), a single octet with value 3
	three := []byte{0x03}

	// 5.  beta_string = Hash(suite_string || three_string || point_to_string(cofactor * Gamma))
	h := v.Hash.New()
	h.Write(v.SuiteString)
	h.Write(three)
	Px, Py := v.EC.ScalarMult(Gx, Gy, big.NewInt(int64(v.cofactor)).Bytes())
	h.Write(v.Point2String(v.EC, Px, Py))

	// 6.  Output beta_string
	return h.Sum(nil), nil
}

//Verify(PublicKey, pi_string, alpha_string)
//
//   Input:
//      Y - public key, an EC point
//      pi_string - VRF proof, octet string of length ptLen+n+qLen
//        alpha_string - VRF input, octet string
//
//   Output:
//      (beta_string, "VALID"), where beta_string is the VRF hash output,
//      octet string of length hLen; or "INVALID"
func (v *ECVRF) Verify(Y *PublicKey, pi, alpha []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode_proof(pi_string)
	Gx, Gy, c, s, err := v.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}
	// 3.  (Gamma, c, s) = D

	// 4.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := v.HashToCurve(v, v.SuiteString, Y, alpha)

	// 5.  U = s*B - c*Y
	U1x, U1y := v.EC.ScalarBaseMult(s.Bytes())
	U2x, U2y := v.EC.ScalarMult(Y.X, Y.Y, c.Bytes())
	Ux, Uy := v.EC.Add(U1x, U1y, U2x, new(big.Int).Neg(U2y)) // -(U2x, U2y) = (U2x, -U2y)

	// 6.  V = s*H - c*Gamma
	V1x, V1y := v.EC.ScalarMult(Hx, Hy, s.Bytes())
	V2x, V2y := v.EC.ScalarMult(Gx, Gy, c.Bytes())
	Vx, Vy := v.EC.Add(V1x, V1y, V2x, new(big.Int).Neg(V2y))

	// 7.  c' = ECVRF_hash_points(H, Gamma, U, V)
	cPrime := v.ECVRFHashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 8.  If c and c' are not equal output "INVALID"
	if c.Cmp(cPrime) != 0 {
		return nil, errors.New("invalid")
	}
	// else, output (ECVRF_proof_to_hash(pi_string), "VALID")
	return v.Proof2Hash(pi)
}
