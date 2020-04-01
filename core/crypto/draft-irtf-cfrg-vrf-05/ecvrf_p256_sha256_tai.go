package vrf

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/hmac"
	"fmt"
	"math/big"

	_ "crypto/sha256" // SHA256 Implementation
)

type (
	p256SHA256TAISuite struct{ *ECVRFParams }
	p256SHA256TAIAux   struct{ params *ECVRFParams }
)

var p256SHA256TAI p256SHA256TAISuite

func initP256SHA256TAI() {
	// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.5
	p256SHA256TAI.ECVRFParams = &ECVRFParams{
		suiteString: []byte{0x01},    // int_to_string(1, 1)
		ec:          elliptic.P256(), // NIST P-256 elliptic curve, [FIPS-186-4] (Section D.1.2.3).
		n:           16,              // 2n = 32, Params().BitSize
		qLen:        32,              // qLen = 32, Params().N.BitLen
		ptLen:       33,              // Size of encoded EC point
		cofactor:    1,
		hash:        crypto.SHA256,
	}
	p256SHA256TAI.ECVRFParams.aux = p256SHA256TAIAux{params: p256SHA256TAI.ECVRFParams}
}

func (s p256SHA256TAISuite) Params() *ECVRFParams {
	return s.ECVRFParams
}

// HashToCurve implements the HashToCurveTryAndIncrement algorithm from section 5.4.1.1.
func (a p256SHA256TAIAux) HashToCurve(pub *PublicKey, alpha []byte) (x, y *big.Int) {
	x, y, _ = a.hashToCurveTryAndIncrement(pub, alpha) // Drop ctr
	return
}

// GenerateNonce implements GenerateNonceRFC6979 // Section 5.4.2.1.
func (a p256SHA256TAIAux) GenerateNonce(sk *PrivateKey, h []byte) (k *big.Int) {
	return generateNonceRFC6979(a.params.hash, sk, h)
}

func (a p256SHA256TAIAux) IntToString(x, xLen uint) []byte {
	return I2OSP(x, xLen) // RFC8017 Section 4.1 (big endian representation)
}

// StringToInt converts an octet string to a nonnegative integer  as specified in Section 5.5.
func (a p256SHA256TAIAux) StringToInt(s []byte) *big.Int {
	return new(big.Int).SetBytes(s) // RFC8017 Section 4.2 (big endian representation)
}

func (a p256SHA256TAIAux) PointToString(x, y *big.Int) []byte {
	return SECG1EncodeCompressed(a.params.ec, x, y)
}

// String2Point converts an octet string to an EC point according to the
// encoding specified in Section 2.3.4 of [SECG1].  This function MUST output
// INVALID if the octet string does not decode to an EC point.
func (a p256SHA256TAIAux) StringToPoint(s []byte) (x, y *big.Int, err error) {
	x, y = SECG1Decode(a.params.ec, s)
	if x == nil || y == nil {
		err = fmt.Errorf("string_to_point failed")
	}
	return
}

// ArbitraryString2Point returns string_to_point(0x02 || h_string)
// Attempts to interpret an arbitrary string as a compressed elliptic code point.
// The input h is a 32-octet string.  Returns either an EC point or "INVALID".
func (a p256SHA256TAIAux) ArbitraryStringToPoint(s []byte) (x, y *big.Int, err error) {
	if got, want := len(s), 32; got != want {
		return nil, nil, fmt.Errorf("len(s): %v, want %v", got, want)
	}
	return a.StringToPoint(append([]byte{0x02}, s...))
}

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
func (a *p256SHA256TAIAux) hashToCurveTryAndIncrement(pub *PublicKey, alpha []byte) (x, y *big.Int, ctr uint) {
	// 1.  ctr = 0
	ctr = 0
	// 2.  PK_string = point_to_string(Y)
	pk := a.PointToString(pub.X, pub.Y)

	// 3.  one_string = 0x01 = int_to_string(1, 1), a single octet with value 1
	one := []byte{0x01}

	// 4.  H = "INVALID"
	h := a.params.hash.New()

	// 5.  While H is "INVALID" or H is EC point at infinity:
	var err error
	for x == nil || err != nil || (zero.Cmp(x) == 0 && zero.Cmp(y) == 0) {
		// A.  ctr_string = int_to_string(ctr, 1)
		ctrString := a.IntToString(ctr, 1)
		// B.  hash_string = Hash(suite_string || one_string ||
		//     PK_string || alpha_string || ctr_string)
		h.Reset()
		h.Write(a.params.suiteString)
		h.Write(one)
		h.Write(pk)
		h.Write(alpha)
		h.Write(ctrString)
		hashString := h.Sum(nil)
		// C.  H = arbitrary_string_to_point(hash_string)
		x, y, err = a.ArbitraryStringToPoint(hashString)
		// D.  If H is not "INVALID" and cofactor > 1, set H = cofactor * H
		// Cofactor for prime ordered curves is 1.
		ctr++
	}
	// 6.  Output H
	return x, y, ctr - 1
}

// 5.4.2.  ECVRF Nonce Generation
//
//    The following subroutines generate the nonce value k in a deterministic
//    pseudorandom fashion.

// generateNonceRFC6979 from section 5.4.2.1 as defined by RFC 6979 section 3.2.
//    Input:
//       SK - an ECVRF secret key
//       h - an octet string
//
//    Output:
//       k - an integer between 1 and q-1
// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#section-5.4.2.1
// https://tools.ietf.org/html/rfc6979#section-3.2
func generateNonceRFC6979(hash crypto.Hash, sk *PrivateKey, h []byte) (k *big.Int) {
	m := h    // Input m is set equal to h_string
	x := sk.x // The secret key x is set equal to the VRF secret scalar x

	// The "suitable for DSA or ECDSA" check in step h.3 is omitted
	// The hash function H is Hash and its output length hlen is set as hLen*8

	// The prime q is the same as in this specification
	q := sk.Params().N

	// qlen is the binary length of q, i.e., the smallest integer such that 2^qlen > q
	// All the other values and primitives as defined in [RFC6979]
	//
	// N, also known as q, is the order of the base point, which generates subgroup Gi.
	qlen := q.BitLen()

	//
	// RFC 6979 section 3.2
	//

	// a.  Process m through the hash function H, yielding: h1 = H(m)
	h1 := hash.New()
	h1.Write(m) // (h1 is a sequence of hlen bits).
	h1Digest := h1.Sum(nil)

	// b.  Set: V = 0x01 0x01 0x01 ... 0x01
	//     such that the length of V, in bits, is equal to 8*ceil(hlen/8).
	//     For instance, on an octet-based system, if H is SHA-256, then V
	//     is set to a sequence of 32 octets of value 1.
	V := bytes.Repeat([]byte{0x01}, hash.Size())

	// c.  Set: K = 0x00 0x00 0x00 ... 0x00
	//     such that the length of K, in bits, is equal to 8*ceil(hlen/8).
	K := make([]byte, hash.Size())

	// d.  Set: K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
	//     In other words, we compute HMAC with key K
	hm := hmac.New(hash.New, K)
	//     over the concatenation of the following, in order:
	//     the current value of V
	hm.Write(V)
	//     a sequence of eight bits of value 0
	hm.Write([]byte{0x00})
	//     the encoding of the (EC)DSA private key x,
	//     Note that the private key x is in the [1, q-1] range, hence a
	//     proper input for int2octets, yielding rlen bits of output, i.e.,
	//     an integral number of octets (rlen is a multiple of 8).
	rlen := ((qlen + 7) >> 3) << 3 //
	hm.Write(int2octets(x, rlen))
	//     and the hashed message
	//     (possibly truncated and extended as specified by the bits2octets transform).
	hm.Write(bits2octets(h1Digest, q, qlen, rlen))
	//     The HMAC result is the new value of K.
	K = hm.Sum(nil)

	// e.  Set:
	//     V = HMAC_K(V)
	vm := hmac.New(hash.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	// f.  Set:
	//     K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
	//     Note that the "internal octet" is 0x01 this time.
	hm = hmac.New(hash.New, K)
	hm.Write(V)
	hm.Write([]byte{0x01})
	hm.Write(int2octets(x, rlen))
	hm.Write(h1Digest)
	K = hm.Sum(nil)

	// g.  Set:
	//     V = HMAC_K(V)
	vm = hmac.New(hash.New, K)
	vm.Write(V)
	V = vm.Sum(nil)

	// h.  Apply the following algorithm until a proper value is found for k:
	for {
		// 1.  Set T to the empty sequence.  The length of T (in bits) is
		//     denoted tlen; thus, at that point, tlen = 0.
		T := make([]byte, 0, qlen/8)
		//  2.  While tlen < qlen, do the following:
		for len(T) < qlen/8 {
			//         V = HMAC_K(V)
			vm = hmac.New(hash.New, K)
			vm.Write(V)
			V = vm.Sum(nil)
			//         T = T || V
			T = append(T, V...)
		}
		//  3.  Compute:  k = bits2int(T)
		k := bits2int(T, qlen)
		one := big.NewInt(1)
		// If that value of k is within the [1,q-1] range, then the generation of k is finished.
		// (The "suitable for DSA or ECDSA" check in step h.3 is omitted.)
		if k.Cmp(one) >= 0 && k.Cmp(q) < 0 {
			return k
		}

		// Otherwise, compute:
		//    K = HMAC_K(V || 0x00)
		km := hmac.New(hash.New, K)
		km.Write(V)
		km.Write([]byte{0x00})
		K = km.Sum(nil)

		//    V = HMAC_K(V)
		km = hmac.New(hash.New, K)
		km.Write(V)
		V = km.Sum(nil)

		// and loop (try to generate a new T, and so on).
	}
}

// int2octets
// rlen is a multiple of 8
// https://tools.ietf.org/html/rfc6979#section-2.3.3
func int2octets(x *big.Int, rlen int) []byte {
	if rlen%8 != 0 {
		panic("rlen is not a multipile of 8")
	}
	// An integer value x less than q (and, in particular, a value that has
	// been taken modulo q) can be converted into a sequence of rlen bits,
	// where rlen = 8*ceil(qlen/8).  This is the sequence of bits obtained
	// by big-endian encoding.  In other words, the sequence bits x_i (for i
	// ranging from 0 to rlen-1) are such that:
	//
	//    x = x_0*2^(rlen-1) + x_1*2^(rlen-2) + ... + x_(rlen-1)
	//
	// We call this transform int2octets.  Since rlen is a multiple of 8
	// (the smallest multiple of 8 that is not smaller than qlen), then the
	// resulting sequence of bits is also a sequence of octets, hence the
	// name.
	b := x.Bytes()
	blen := len(b) * 8
	if blen < rlen {
		// left pad with rlen - blen bits
		b = append(make([]byte, (rlen-blen)/8), b...)
	}
	if blen > rlen {
		// truncate to blen bits
		b = b[:rlen/8]
	}
	return b
}

// bits2octets takes as input a sequence of blen bits and outputs a sequence of rlen bits.
// https://tools.ietf.org/html/rfc6979#section-2.3.4
func bits2octets(b []byte, q *big.Int, qlen, rlen int) []byte {
	// 1.  The input sequence b is converted into an integer value z1 through
	//     the bits2int transform:
	z1 := bits2int(b, qlen)

	// 2.  z1 is reduced modulo q, yielding z2 (an integer between 0 and q-1, inclusive):
	//     Note that since z1 is less than 2^qlen, that modular reduction
	//     can be implemented with a simple conditional subtraction:
	//     z2 = z1-q if that value is non-negative; otherwise, z2 = z1.
	z2 := new(big.Int).Sub(z1, q)
	if z2.Sign() < 0 {
		z2 = z1
	}

	// 3.  z2 is transformed into a sequence of octets (a sequence of rlen bits)
	//     by applying int2octets.
	return int2octets(z2, rlen)
}

// bits2int takes as input a sequence of blen bits and outputs a non-negative
// integer that is less than 2^qlen.
// https://tools.ietf.org/html/rfc6979#section-2.3.2
func bits2int(b []byte, qlen int) *big.Int {
	blen := len(b) * 8
	v := new(big.Int).SetBytes(b)
	// 1.  The sequence is first truncated or expanded to length qlen:
	if qlen < blen {
		// if qlen < blen, then the qlen leftmost bits are kept, and
		// subsequent bits are discarded;
		v = new(big.Int).Rsh(v, uint(blen-qlen))
	}
	// otherwise, qlen-blen bits (of value zero) are added to the
	// left of the sequence (i.e., before the input bits in the
	// sequence order).

	// 2.  The resulting sequence is then converted to an integer value
	//     using the big-endian convention: if input bits are called b_0
	//     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
	//     is: b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
	return v
}
