package vrf

import (
	"fmt"
	"math/big"
)

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
func (v *ECVRF) decodeProof(pi []byte) (Gx, Gy, c, s *big.Int, err error) {
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
	Gx, Gy = v.String2Point(v.EC, gStr)
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
