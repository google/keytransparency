package vrf

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
	"sync"
)

var initonce sync.Once

func initAll() {
	initP256SHA256TAI()
}

// ECVRF_P256_SHA256_TAI returns a elliptic curve based VRF instantiated with
// P256, SHA256, and the "Try And Increment" strategy for hashing to the curve.
func ECVRF_P256_SHA256_TAI() VRF {
	initonce.Do(initAll)
	return p256SHA256TAI
}

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

// ECVRF_hash_points(P1x P1y, P2x, P2y, ..., PMx, PMy)
//
// Input:
//
//    P1...PM - EC points in G
//
// Output:
//
//    c - hash value, integer between 0 and 2^(8n)-1
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.3
func (v *ECVRF) ECVRFHashPoints(pm ...*big.Int) *big.Int {
	// 1.  two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
	two_string := byte(0x02)

	// 2.  Initialize str = suite_string || two_string
	str := append(v.SuiteString, two_string)

	// 3.  for PJ in [P1, P2, ... PM]:
	for i := 0; i < len(pm); i += 2 {
		// str = str || point_to_string(PJ)
		str = append(str, v.Point2String(v.EC, pm[i], pm[i+1])...)
	}

	// 4.  c_string = Hash(str)
	hc := v.Hash.New()
	hc.Write(str)
	cString := hc.Sum(nil)

	// 5.  truncated_c_string = c_string[0]...c_string[n-1]
	n := v.EC.Params().BitSize / 8 / 2 //   2n = qLen = 32
	// 6.  c = string_to_int(truncated_c_string)
	c := new(big.Int).SetBytes(cString[:n])
	return c
}
