package vrf

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"math/big"
)

// 5.4.2.  ECVRF Nonce Generation
//
//    The following subroutines generate the nonce value k in a deterministic
//    pseudorandom fashion.

// GenerateNonceRFC6979 from section 5.4.2.1 as defined by RFC 6979 section 3.2.
//    Input:
//       SK - an ECVRF secret key
//       h - an octet string
//
//    Output:
//       k - an integer between 1 and q-1
func GenerateNonceRFC6979(hash crypto.Hash, SK *PrivateKey, h []byte) (k *big.Int) {
	m := h    // Input m is set equal to h_string
	x := SK.x // The secret key x is set equal to the VRF secret scalar x

	// The "suitable for DSA or ECDSA" check in step h.3 is omitted
	// The hash function H is Hash and its output length hlen is set as hLen*8

	// The prime q is the same as in this specification
	q := SK.Params().N

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
	//     where '||' denotes concatenation.  In other words, we compute
	//     HMAC with key K, over the concatenation of the following, in
	//     order: the current value of V, a sequence of eight bits of value
	//     0, the encoding of the (EC)DSA private key x, and the hashed
	//     message (possibly truncated and extended as specified by the
	//     bits2octets transform).  The HMAC result is the new value of K.
	//     Note that the private key x is in the [1, q-1] range, hence a
	//     proper input for int2octets, yielding rlen bits of output, i.e.,
	//     an integral number of octets (rlen is a multiple of 8).
	hm := hmac.New(hash.New, K)
	hm.Write(V)
	hm.Write([]byte{0x00})
	hm.Write(x.Bytes()) // int2octets
	hm.Write(h1Digest)  // bits2octets
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
	hm.Write(x.Bytes())
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
		z1 = z1
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
	} else {
		// otherwise, qlen-blen bits (of value zero) are added to the
		// left of the sequence (i.e., before the input bits in the
		// sequence order).
	}

	// 2.  The resulting sequence is then converted to an integer value
	//     using the big-endian convention: if input bits are called b_0
	//     (leftmost) to b_(qlen-1) (rightmost), then the resulting value
	//     is: b_0*2^(qlen-1) + b_1*2^(qlen-2) + ... + b_(qlen-1)*2^0
	return v
}
