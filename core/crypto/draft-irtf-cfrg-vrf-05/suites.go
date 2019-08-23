package vrf

type Suite struct {
	suite []byte
	curve elliptic.Curve
	hash  hash.Hash
	nonce func()
	int2string
	string2int
	point2string
}

func ECVRF_P256_SHA256_TAI() VRF {
	s := ECVRF{
		suite: 0x01,
		E:     elliptic.P256(),
		Hash:  sha256.New(),
		// nonce: // Section 5.4.2.1.
		// int2string: // Section 4.1
		// string2int: // Section 4.2
		// point2string: // Section 2.3.3 of [SECG1] with point compression on. Ptlen =33
		// string2point: // Section 2.3.4 of [SECG1]
		// abitrary_string2point: // string_to_point(0x02 || h_string)
		HashToCurve: // Section 5.4.1.1.
	}
}

// ECVRF returns a Elliptic Curve Verifiable Random Function that satisfies the
// trusted uniqueness, trusted collision resistance, and full pseudorandomness
// properties.
func ECVRF_P256_SHA256_SWU() VRF {
	s := ECVRF{
		suite: []byte(0x02),
		// ECVRF_hash_to_curve: // Section 5.4.1.3
	}
}
