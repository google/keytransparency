package vrf

import "math/big"

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
