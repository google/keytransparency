package vrf

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"
)

func hd(t *testing.T, s string) []byte {
	t.Helper()
	s = strings.ReplaceAll(s, " ", "")
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// test vector from https://tools.ietf.org/html/rfc6979#appendix-A.2.5
func TestGenerateNonceRFC6979(t *testing.T) {
	SK := &PrivateKey{
		x:         new(big.Int),
		PublicKey: PublicKey{Curve: elliptic.P256(), X: new(big.Int), Y: new(big.Int)},
	}
	SK.x.SetString("C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721", 16)
	SK.PublicKey.X.SetString("60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6", 16)
	SK.PublicKey.Y.SetString("7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299", 16)
	m := []byte("sample")

	if got, want := generateNonceRFC6979(crypto.SHA256, SK, m).Bytes(),
		hd(t, "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"); !bytes.Equal(got, want) {
		t.Errorf("k: %x, want %x", got, want)
	}
}

// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-06#appendix-A.1
func TestVectorsECVRF_P256_SHA256_TAI(t *testing.T) {
	for i, tc := range []struct {
		SK      []byte
		PK      []byte
		alpha   []byte
		wantCtr uint
		H       []byte
		k       []byte
		U       []byte // k*B
		V       []byte // k*H
		pi      []byte
		beta    []byte
	}{
		{
			SK:      hd(t, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
			PK:      hd(t, "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
			alpha:   []byte("sample"), // 0x73616d706c65, // (ASCII "sample")
			wantCtr: 0,                // try_and_increment succeeded on ctr = 0
			H:       hd(t, "02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e"),
			k:       hd(t, "b7de5757b28c349da738409dfba70763ace31a6b15be8216991715fbc833e5fa"),
			U:       hd(t, "030286d82c95d54feef4d39c000f8659a5ce00a5f71d3a888bd1b8e8bf07449a50"),
			V:       hd(t, "03e4258b4a5f772ed29830050712fa09ea8840715493f78e5aaaf7b27248efc216"),
			pi: hd(t, "029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c5"+
				"24347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb6"+
				"1b201059f89186e7175af796d65e7"),
			beta: hd(t, "59ca3801ad3e981a88e36880a3aee1df38a0472d5be52d6e39663ea0314e594c"),
		},
		{
			SK:      hd(t, "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"),
			PK:      hd(t, "0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"),
			alpha:   []byte("test"), // 74657374
			wantCtr: 0,              // try_and_increment succeeded on ctr = 0
			H:       hd(t, "02ca565721155f9fd596f1c529c7af15dad671ab30c76713889e3d45b767ff6433"),
			k:       hd(t, "c3c4f385523b814e1794f22ad1679c952e83bff78583c85eb5c2f6ea6eee2e7d"),
			U:       hd(t, "034b3793d1088500ec3cccdea079beb0e2c7cdf4dccef1bbda379cc06e084f09d0"),
			V:       hd(t, "02427cdb19aa5dd645e153d6bd8c0d81a658deee37b203edfd461953f301c4f868"),
			pi: hd(t, "03873a1cce2ca197e466cc116bca7b1156fff599be67ea40b17256c4f34ba254"+
				"9c94ffd2b31588b5fe034fd92c87de5b520b12084da6c4ab63080a7c5467094a1ee84"+
				"b80b59aca54bba2e2baa0d108191b"),
			beta: hd(t, "dc85c20f95100626eddc90173ab58d5e4f837bb047fb2f72e9a408feae5bc6c1"),
		},
		{
			SK:      hd(t, "2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8"),
			PK:      hd(t, "03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d"),
			alpha:   []byte("Example of ECDSA with ansip256r1 and SHA-256"),
			wantCtr: 1, // try_and_increment succeeded on ctr = 1
			H:       hd(t, "02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d"),
			k:       hd(t, "6ac8f1efa102bdcdcc8db99b755d39bc995491e3f9dea076add1905a92779610"),
			U:       hd(t, "034bf7bd3638ef06461c6ec0cfaef7e58bfdaa971d7e36125811e629e1a1e77c8a"),
			V:       hd(t, "03b8b33a134759eb8c9094fb981c9590aa53fd13d35042575067a7bd7c5bc6287b"),
			pi: hd(t, "02abe3ce3b3aa2ab3c6855a7e729517ebfab6901c2fd228f6fa066f15ebc9b9d"+
				"415a680736f7c33f6c796e367f7b2f467026495907affb124be9711cf0e2d05722d3a"+
				"33e11d0c5bf932b8f0c5ed1981b64"),
			beta: hd(t, "e880bde34ac5263b2ce5c04626870be2cbff1edcdadabd7d4cb7cbc696467168"),
		},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v := ECVRFP256SHA256TAI()
			p := v.Params()
			a := p256SHA256TAIAux{params: p}

			sk := NewKey(p.ec, tc.SK)

			// 1.  Use SK to derive the VRF secret scalar x and the VRF public key Y = x*B
			x := sk.x // In this ciphersuite, the secret scalar x is equal to the private key SK.
			pk := sk.Public()

			// 2.  H = ECVRF_hash_to_curve(suite_string, Y, alpha_string)
			Hx, Hy, ctr := a.hashToCurveTryAndIncrement(pk, tc.alpha)
			if ctr != tc.wantCtr {
				t.Fatalf("HashToCurve: ctr: %v, want %v", ctr, tc.wantCtr)
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
