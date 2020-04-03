// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vrf

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
)

func TestCMOV(t *testing.T) {
	n := elliptic.P256().Params().N
	b := elliptic.P256().Params().B
	for _, tc := range []struct {
		if0, if1, want *big.Int
		s              int64
	}{
		{if1: big.NewInt(5), if0: big.NewInt(6), s: 0, want: big.NewInt(6)},
		{if1: big.NewInt(5), if0: big.NewInt(6), s: 1, want: big.NewInt(5)},
		{if1: big.NewInt(0xFFFF), if0: big.NewInt(0), s: 1, want: big.NewInt(0xFFFF)},
		{if1: big.NewInt(0xFFFF), if0: big.NewInt(0), s: 0, want: big.NewInt(0)},
		{if1: n, if0: b, s: 0, want: b},
		{if1: n, if0: b, s: 1, want: n},
	} {
		if got := cmov(tc.if1, tc.if0, big.NewInt(tc.s)); got.Cmp(tc.want) != 0 {
			t.Errorf("cmov(%v, %v, %v): %v, want %v", tc.if1, tc.if0, tc.s, got, tc.want)
		}
	}
}

// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#appendix-A.2
func TestVectorsECVRF_P256_SHA256_SWU(t *testing.T) {
	for i, tc := range []struct {
		SK    []byte
		PK    []byte
		alpha []byte
		t, w  []byte
		H     []byte
		k     []byte
		U     []byte // k*B
		V     []byte // k*H
		pi    []byte
		beta  []byte
	}{
		{
			SK:    hd(t, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
			PK:    hd(t, "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
			alpha: []byte("sample"), // 0x73616d706c65, // (ASCII "sample")
			t:     hd(t, "f1523667d029b9119a319a5bb316ff846691600e3552514ec4f93f9c84d65a4f"),
			w:     hd(t, "d8125c3ae82fc2b7f1c326b6f3dbfdf3583272336a60cb08efb84e002e98a3b3"),
			H:     hd(t, "027827143876a58c2189402306c6ff6f7f9a7271067f3ed28eb63790d58a84fdd6"),
			k:     hd(t, "cabfb61ad47b639814365bcbe2cc48a9ad4e3cfe61172aced7d539d47f459654"),
			U:     hd(t, "023cd2988db2421dbfd5cefb8c2342ed2413160d4f6521d301e7b2995fe8551bd6"),
			V:     hd(t, "025443fe6f00281ff3afa0ff93db2ce9cb20dfcafb7c17b78c9e912d26f4e22cf2"),
			pi: hd(t, "021d684d682e61dd76c794eef43988a2c61fbdb2af64fbb4f435cc2a842b0024"+
				"c3b3056b7310e0130317274a58e57317c469b46fe5ab6a34463d7ecb2a7ae1d808381"+
				"f53c0f6aaaebe62195cfd14526f03"),
			beta: hd(t, "143f36bf7175053315693cfcfdff5aebb13e5eb9c47f897f53f81561993cfcd2"),
		},
		{
			SK:    hd(t, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
			PK:    hd(t, "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
			alpha: []byte("test"), // 74657374
			t:     hd(t, "e20da1d7386cb673deffec63d47ec65862dce55f113be168fa45cba2a6c1ddbc"),
			w:     hd(t, "0eed10be2937c902c9612d80b8ea5b0783f81c419faedd57efc84e6dfcfe2c72"),
			H:     hd(t, "020e6c14efc8bc7150a3467aafa78be9856a2c6e405bdcc50f767fe638569d0172"),
			k:     hd(t, "eb2035e5d6993b96589937c36482c647dab2b420fd152ffe026437b0b6c22e26"),
			U:     hd(t, "038bf7231765143e6de2cef1bbd79dd80729a320dbc040ecd8f3d937b756b68e56"),
			V:     hd(t, "0365e6610ff260aef9721450e2353677470e179573937756a803df1df9680ca698"),
			pi: hd(t, "0376b758f457d2cabdfaeb18700e46e64f073eb98c119dee4db6c5bb1eaf6778"+
				"0654504c6e583fd6eb129195b1836f91a6dd16504f957c8dedb653806952e3b0217ef"+
				"187b87b9dda851f0a515f4dcc09d1"),
			beta: hd(t, "6b5bb622a6bc1387a7dcc4f46cfdcc3bce67669b32f3bc39e047c3b6cd3e65d9"),
		},
		{
			SK:    hd(t, "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8"),
			PK:    hd(t, "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d"),
			alpha: []byte("Example of ECDSA with ansip256r1 and SHA-256"),
			t:     hd(t, "e93da6ba2bca714061dc94c8c513343ad11bfc9678339e4a8bd86a08232aa6d7"),
			w:     hd(t, "76f564cca31934c80dd2a285ba43543df63a078b132c8f34d2ab1b7089cb3401"),

			H: hd(t, "02429690b91e1783cd0d7e393db07cc44b48c226cb837adb2282251cabf431a484"),
			k: hd(t, "6181315ddb4f4d159ce8cbad48d5454625ccbf47c46c4cabd972be72b372a50b"),
			U: hd(t, "02c6dac6f9a51b79b8bc928a67320f4d569090b8c6b86f011ddf898788559c134d"),
			V: hd(t, "033f8070c0a09ac089d1ceffc384d3f25bb0597f63161ca82431331278baf1568f"),
			pi: hd(t, "035e844533a7c5109ab3dffd04f2ef0d38d679101124f15243199ce92f0f2947"+
				"7ca8e8f01b40c77c61a169ad6db9d76fae7938e94a4338bca9c586c8e266ead7a6b24"+
				"b769d3d34efc85f6cdb82d96bb717"),
			beta: hd(t, "be1dcb17e9815ac6acf819e7ad4b75e575eafad25915c2608959d780364fc912"),
		},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v := ECVRFP256SHA256SWU()
			p := v.Params()
			a := p256SHA256SWUAux{
				params:           p,
				p256SHA256TAIAux: p256SHA256TAIAux{params: p},
			}

			sk := NewKey(p.ec, tc.SK)

			// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
			x := sk.x // In this ciphersuite, the secret scalar x is equal to the private key SK.
			pk := sk.Public()

			// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
			Hx, Hy, T, w := a.hashToCurveSimplifiedSWU(pk, tc.alpha)
			if want := new(big.Int).SetBytes(tc.t); T.Cmp(want) != 0 {
				t.Fatalf("HashToCurve: t: %v, want %v", t, want)
			}
			if want := new(big.Int).SetBytes(tc.w); w.Cmp(want) != 0 {
				t.Fatalf("HashToCurve: w: %x, want %x", w.Bytes(), tc.w)
			}

			// 3.  h_string = point_to_string(H)
			hString := a.PointToString(Hx, Hy)
			if got := hString; !bytes.Equal(got, tc.H) {
				t.Fatalf("H: %x, want %x", got, tc.H)
			}

			// 4.  Gamma = x*H
			Gx, Gy := p.ec.ScalarMult(Hx, Hy, x.Bytes())

			// 5.  k = ECVRF_nonce_generation(SK, h_string)
			k := a.GenerateNonce(sk, hString)
			if got := k.Bytes(); !bytes.Equal(got, tc.k) {
				t.Fatalf("k: %x, want %x", k, tc.k)
			}

			// 6.  c = ECVRF_hash_points(H, Gamma, k*B, k*H)
			Ux, Uy := p.ec.ScalarBaseMult(k.Bytes())
			if got, want := Ux.Bytes(), tc.U[1:]; !bytes.Equal(got, want) {
				t.Errorf("U: %x, want %x", got, want)
			}
			Vx, Vy := p.ec.ScalarMult(Hx, Hy, k.Bytes())
			if got, want := Vx.Bytes(), tc.V[1:]; !bytes.Equal(got, want) {
				t.Errorf("V: %x, want %x", got, want)
			}

			c := p.hashPoints(Hx, Hy, Gx, Gy, Ux, Uy, Vx, Vy)

			// 7.  s = (k + c*x) mod q
			s1 := new(big.Int).Mul(c, x)
			s2 := new(big.Int).Add(k, s1)
			s := new(big.Int).Mod(s2, p.ec.Params().N)

			// 8.  pi_string = point_to_string(Gamma) || int_to_string(c, n) || int_to_string(s, qLen)
			piB := new(bytes.Buffer)
			piB.Write(a.PointToString(Gx, Gy))
			piB.Write(c.Bytes())
			t.Logf("n: %v", len(c.Bytes()))
			piB.Write(s.Bytes())

			if got := piB.Bytes(); !bytes.Equal(got, tc.pi) {
				t.Errorf("pi: %x, want %x", got, tc.pi)
			}

			pi := v.Prove(sk, tc.alpha)
			if !bytes.Equal(pi, tc.pi) {
				t.Errorf("Prove(%s): %x, want %x", tc.alpha, pi, tc.pi)
			}

			beta, err := v.ProofToHash(pi)
			if err != nil {
				t.Fatalf("Proof2Hash(): %v", err)
			}
			if !bytes.Equal(beta, tc.beta) {
				t.Errorf("beta: %x, want %x", beta, tc.beta)
			}

			beta2, err := v.Verify(pk, pi, tc.alpha)
			if err != nil {
				t.Errorf("Verify(): %v", err)
			}
			if !bytes.Equal(beta, beta2) {
				t.Errorf("beta: %x, beta2: %x", beta, beta2)
			}
		})
	}
}
