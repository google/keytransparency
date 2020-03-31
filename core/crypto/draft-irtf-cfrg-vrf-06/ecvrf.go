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

// ECVRFParams holds shared values across ECVRF implementations.
// ECVRFParams also has generic algorithms that rely on ECVRFAux for specific sub algorithms.
type ECVRFParams struct {
	suiteString []byte         // single nonzero octet specifying the ECVRF ciphersuite
	ec          elliptic.Curve // Elliptic curve defined over F
	//   G - subgroup of E of large prime order.
	//   q - prime order of group G, ec.Params().N
	//   B - generator of group G, ec.Params.{Gx,Gy}
	n        int // 2n  - length, in octets, of a field element in F.
	ptLen    int // length, in octets, of an EC point encoded as an octet string
	qLen     int // length of q in octets. (note that in the typical case, qLen equals 2n or is close to 2n)
	cofactor int //number of points on E divided by q
	hash     crypto.Hash
	aux      ECVRFAux // Auxillary functions
}

// ECVRFAux contains auxillary functions nessesary for the computation of ECVRF.
type ECVRFAux interface {
	// HashToCurve is a collision resistant hash of strings to an EC point;
	// options described in Section 5.4.1 and specified in Section 5.5.
	// HashToCurveTryAndIncrement takes in the VRF input alpha and converts
	// it to H, an EC point in G.
	HashToCurve(Y *PublicKey, alpha []byte) (x, y *big.Int)

	// GenerateNonoce generates the nonce value k in a deterministic pseudorandom fashion.
	GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int)

	// IntToString converts a nonnegative integer to an octet string of a specified length.
	IntToString(x, xLen uint) []byte

	// StringToInt converts an octet string to a nonnegative integer.
	// TODO(gbelvin): implement
	// StringToInt(x int) int

	// PointToString converts an EC point to an octet string according to
	// the encoding specified in Section 2.3.3 of [SECG1] with point
	// compression on.  This implies ptLen = 2n + 1 = 33.
	PointToString(Px, Py *big.Int) []byte

	// StringToInt converts an octet string a_string to a nonnegative
	// integer as specified in Section 5.5.

	// StringToPoint converts an octet string to an EC point
	// This function MUST output INVALID if the octet string does not
	// decode to an EC point.
	// TODO(gbelvin): return err
	StringToPoint(h []byte) (Px, Py *big.Int)

	// ArbitraryStringToPoint(s) = string_to_point(0x02 || s)
	// (where 0x02 is a single octet with value 2, 0x02=int_to_string(2, 1)).
	// The input s is a 32-octet string and the output is either an EC point or "INVALID".
	ArbitraryStringToPoint(s []byte) (Px, Py *big.Int, err error)
}

// Proof returns proof pi that beta is the correct hash output.
// SK - VRF private key
// alpha - input alpha, an octet string
// Returns pi - VRF proof, octet string of length ptLen+n+qLen
func (v *ECVRFParams) Prove(sk *PrivateKey, alpha []byte) []byte {
	// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
	x := sk.x
	pk := sk.Public()

	// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := v.aux.HashToCurve(pk, alpha)

	// 3.  h_string = point_to_string(H)
	hString := v.aux.PointToString(Hx, Hy)

	// 4.  Gamma = x*H
	Gx, Gy := v.ec.ScalarMult(Hx, Hy, x.Bytes())

	// 5.  k = ECVRF_nonce_generation(SK, h_string)
	k := v.aux.GenerateNonce(sk, hString)

	// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)
	Ux, Uy := v.ec.ScalarBaseMult(k.Bytes())
	Vx, Vy := v.ec.ScalarMult(Hx, Hy, k.Bytes())
	c := v.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 7.  s = (k + c*x) mod q
	s1 := new(big.Int).Mul(c, x)
	s2 := new(big.Int).Add(k, s1)
	s := new(big.Int).Mod(s2, v.ec.Params().N)

	// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
	pi := new(bytes.Buffer)
	pi.Write(v.aux.PointToString(Gx, Gy)) // ptLen
	pi.Write(c.Bytes())                   // n
	pi.Write(s.Bytes())                   // qLen

	return pi.Bytes()
}

// ProofToHash returns beta
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
func (v *ECVRFParams) ProofToHash(pi []byte) (beta []byte, err error) {
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
	h := v.hash.New()
	h.Write(v.suiteString)
	h.Write(three)
	Px, Py := v.ec.ScalarMult(Gx, Gy, big.NewInt(int64(v.cofactor)).Bytes())
	h.Write(v.aux.PointToString(Px, Py))

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
func (v *ECVRFParams) Verify(Y *PublicKey, pi, alpha []byte) (beta []byte, err error) {
	// 1.  D = ECVRF_decode_proof(pi_string)
	Gx, Gy, c, s, err := v.decodeProof(pi)
	// 2.  If D is "INVALID", output "INVALID" and stop
	if err != nil {
		return nil, err
	}
	// 3.  (Gamma, c, s) = D

	// 4.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
	Hx, Hy := v.aux.HashToCurve(Y, alpha)

	// 5.  U = s*B - c*Y
	U1x, U1y := v.ec.ScalarBaseMult(s.Bytes())
	U2x, U2y := v.ec.ScalarMult(Y.X, Y.Y, c.Bytes())
	Ux, Uy := v.ec.Add(U1x, U1y, U2x, new(big.Int).Neg(U2y)) // -(U2x, U2y) = (U2x, -U2y)

	// 6.  V = s*H - c*Gamma
	V1x, V1y := v.ec.ScalarMult(Hx, Hy, s.Bytes())
	V2x, V2y := v.ec.ScalarMult(Gx, Gy, c.Bytes())
	Vx, Vy := v.ec.Add(V1x, V1y, V2x, new(big.Int).Neg(V2y))

	// 7.  c' = ECVRF_hash_points(H, Gamma, U, V)
	cPrime := v.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

	// 8.  If c and c' are not equal output "INVALID"
	if c.Cmp(cPrime) != 0 {
		return nil, errors.New("invalid")
	}
	// else, output (ECVRF_proof_to_hash(pi_string), "VALID")
	return v.ProofToHash(pi)
}

//
// Auxilary functions
//

// hashPoints(P1x P1y, P2x, P2y, ..., PMx, PMy)
//
// Input:
//    P1...PM - EC points in G
//
// Output:
//    c - hash value, integer between 0 and 2^(8n)-1
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.3
func (v *ECVRFParams) hashPoints(pm ...*big.Int) *big.Int {
	// 1.  two_string = 0x02 = int_to_string(2, 1), a single octet with value 2
	two_string := byte(0x02)

	// 2.  Initialize str = suite_string || two_string
	str := append(v.suiteString, two_string)

	// 3.  for PJ in [P1, P2, ... PM]:
	for i := 0; i < len(pm); i += 2 {
		// str = str || point_to_string(PJ)
		str = append(str, v.aux.PointToString(pm[i], pm[i+1])...)
	}

	// 4.  c_string = Hash(str)
	hc := v.hash.New()
	hc.Write(str)
	cString := hc.Sum(nil)

	// 5.  truncated_c_string = c_string[0]...c_string[n-1]
	// 6.  c = string_to_int(truncated_c_string)
	c := new(big.Int).SetBytes(cString[:v.n])
	return c
}

// decodeProof
//
//    Input:
//       pi_string - VRF proof, octet string (ptLen+n+qLen octets)
//
//    Output:
//       Gx, Gy - Gamma - EC point
//       c - integer between 0 and 2^(8n)-1
//       s - integer between 0 and 2^(8qLen)-1
//       or "INVALID"
//
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.4
func (v *ECVRFParams) decodeProof(pi []byte) (Gx, Gy, c, s *big.Int, err error) {
	ptLen, n, qLen := v.ptLen, v.n, v.qLen
	if got, want := len(pi), ptLen+n+qLen; got != want {
		return nil, nil, nil, nil, fmt.Errorf("len(pi): %v, want %v", got, want)
	}

	//    1.  let gamma_string = pi_string[0]...p_string[ptLen-1]
	gStr := pi[:ptLen]
	//    2.  let c_string = pi_string[ptLen]...pi_string[ptLen+n-1]
	cStr := pi[ptLen : ptLen+n]
	//    3.  let s_string =pi_string[ptLen+n]...pi_string[ptLen+n+qLen-1]
	sStr := pi[ptLen+n : ptLen+n+qLen]

	//    4.  Gamma = string_to_point(gamma_string)
	Gx, Gy = v.aux.StringToPoint(gStr)
	//    5.  if Gamma = "INVALID" output "INVALID" and stop.
	if Gx == nil || Gy == nil {
		return nil, nil, nil, nil, fmt.Errorf("string_to_point failed")
	}

	//    6.  c = string_to_int(c_string)
	c = new(big.Int).SetBytes(cStr)
	//    7.  s = string_to_int(s_string)
	s = new(big.Int).SetBytes(sStr)
	//    8.  Output Gamma, c, and s
	return
}
