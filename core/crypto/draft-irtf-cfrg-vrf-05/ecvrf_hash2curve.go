package vrf

import (
	"math/big"
)

var zero big.Int

// HashToCurveTryAndIncrement implements HashToCurve in a simple and generic
// way that works for any elliptic curve.
//
// The running time of this algorithm depends on alpha. For the ciphersuites
// specified in Section 5.5, this algorithm is expected to find a valid curve
// point after approximately two attempts (i.e., when ctr=1) on average.
//
// However, because the running time of algorithm depends on alpha, this
// algorithm SHOULD be avoided in applications where it is important that the
// VRF input alpha remain secret.
//
// Inputs:
// - `suite` - a single octet specifying ECVRF ciphersuite.
// - `Y` - public key, an EC point
// - `alpha` - value to be hashed, an octet string
// Output:
// - `H` - hashed value, a finite EC point in G
// - `ctr` - integer, number of suite byte, attempts to find a valid curve point
func HashToCurveTryAndIncrement(v *ECVRFSuite, Y *PublicKey, alpha []byte) (Hx, Hy *big.Int, ctr uint) {
	// 1.  ctr = 0
	ctr = 0
	// 2.  PK_string = point_to_string(Y)
	pk := v.Point2String(v.EC, Y.X, Y.Y)

	// 3.  one_string = 0x01 = int_to_string(1, 1), a single octet with value 1
	one := []byte{0x01}

	// 4.  H = "INVALID"
	h := v.Hash.HashFunc().New()

	// 5.  While H is "INVALID" or H is EC point at infinity:
	for Hx == nil || (zero.Cmp(Hx) == 0 && zero.Cmp(Hy) == 0) {
		// A.  ctr_string = int_to_string(ctr, 1)
		ctrString := v.Int2String(ctr, 1)
		// B.  hash_string = Hash(suite_string || one_string ||
		//     PK_string || alpha_string || ctr_string)
		h.Reset()
		h.Write([]byte{v.suite})
		h.Write(one)
		h.Write(pk)
		h.Write(alpha)
		h.Write(ctrString)
		hashString := h.Sum(nil)
		// C.  H = arbitrary_string_to_point(hash_string)
		Hx, Hy = v.ArbitraryString2Point(v.EC, hashString)
		// D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
		// Cofactor for prime ordered curves is 1.
		ctr++
	}
	// 6.  Output H
	return Hx, Hy, ctr - 1
}

func HashToCurveTAI(v *ECVRFSuite, Y *PublicKey, alpha []byte) (Hx, Hy *big.Int) {
	Hx, Hy, _ = HashToCurveTryAndIncrement(v, Y, alpha) // Drop ctr
	return
}
