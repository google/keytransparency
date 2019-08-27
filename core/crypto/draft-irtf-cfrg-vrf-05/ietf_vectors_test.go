package vrf

import "testing"

func TestECVRF_P256_SHA256_TAI(t *testing.T) {
	for _, tc := range []struct {
		SKx     []byte
		PK      []byte
		alpha   []byte
		wantCtr int
		H       []byte
		k       []byte
		U       []byte
		V       []byte
		pi      []byte
		beta    []byte
	}{
		{
			SK:      0xc9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721,
			PK:      0x0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6,
			alpha:   []byte("sample"), // 0x73616d706c65, // (ASCII "sample")
			wantCtr: 0,                // try_and_increment succeded on ctr = 0
			H:       0x02e2e1ab1b9f5a8a68fa4aad597e7493095648d3473b213bba120fe42d1a595f3e,
			/*
			   k = b7de5757b28c349da738409dfba70763ace31a6b15be8216991715fbc833e5fa
			   U = k*B = 030286d82c95d54feef4d39c000f8659a5ce00a5f71d3a888bd1b8e8bf07449a50
			   V = k*H = 03e4258b4a5f772ed29830050712fa09ea8840715493f78e5aaaf7b27248efc216
			   pi = 029bdca4cc39e57d97e2f42f88bcf0ecb1120fb67eb408a856050dbfbcbf57c5
			   24347fc46ccd87843ec0a9fdc090a407c6fbae8ac1480e240c58854897eabbc3a7bb6
			   1b201059f89186e7175af796d65e7
			   beta : 59ca3801ad3e981a88e36880a3aee1df38a0472d5be52d6e39663ea0314e594c,
			*/
		},
		/*
			   {
				   SK = x = c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721
				   PK = 0360fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
				   alpha = 74657374 // (ASCII "test")
				   try_and_increment succeded on ctr = 0
				   H = 02ca565721155f9fd596f1c529c7af15dad671ab30c76713889e3d45b767ff6433
				   k = c3c4f385523b814e1794f22ad1679c952e83bff78583c85eb5c2f6ea6eee2e7d
				   U = k*B = 034b3793d1088500ec3cccdea079beb0e2c7cdf4dccef1bbda379cc06e084f09d0
				   V = k*H = 02427cdb19aa5dd645e153d6bd8c0d81a658deee37b203edfd461953f301c4f868
				   pi = 03873a1cce2ca197e466cc116bca7b1156fff599be67ea40b17256c4f34ba254
				   9c94ffd2b31588b5fe034fd92c87de5b520b12084da6c4ab63080a7c5467094a1ee84
				   b80b59aca54bba2e2baa0d108191b
				   beta = dc85c20f95100626eddc90173ab58d5e4f837bb047fb2f72e9a408feae5bc6c1
			   },
			   {
				   SK = x = 2ca1411a41b17b24cc8c3b089cfd033f1920202a6c0de8abb97df1498d50d2c8
				   PK = 03596375e6ce57e0f20294fc46bdfcfd19a39f8161b58695b3ec5b3d16427c274d
				   alpha = 4578616d706c65206f66204543445341207769746820616e736970323536723120616e64205348412d323536 // (ASCII "Example of ECDSA with ansip256r1 and SHA-256")
				   try_and_increment succeded on ctr = 1
				   H = 02141e41d4d55802b0e3adaba114c81137d95fd3869b6b385d4487b1130126648d
				   k = 6ac8f1efa102bdcdcc8db99b755d39bc995491e3f9dea076add1905a92779610
				   U = k*B = 034bf7bd3638ef06461c6ec0cfaef7e58bfdaa971d7e36125811e629e1a1e77c8a
				   V = k*H = 03b8b33a134759eb8c9094fb981c9590aa53fd13d35042575067a7bd7c5bc6287b
				   pi = 02abe3ce3b3aa2ab3c6855a7e729517ebfab6901c2fd228f6fa066f15ebc9b9d
				   415a680736f7c33f6c796e367f7b2f467026495907affb124be9711cf0e2d05722d3a
				   33e11d0c5bf932b8f0c5ed1981b64
				   beta = e880bde34ac5263b2ce5c04626870be2cbff1edcdadabd7d4cb7cbc696467168
			   }
		*/
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			v := ECVRF_P256_SHA256_TAI()
			sk := NewKey(tc.SK)
			Hx, Hy, ctr := v.HashToCurveTryAndIncrement(pk, tc.alpha)
			if ctr != tc.wantCtr {
				t.Fatalf("HashToCurve: ctr: %v, want %v", ctr, tc.wantCtr)
			}
			if got := v.Point2String(Hx, Hy); !bytes.Equal(got, tc.H) {
				t.Fatalf("H: %x, want %x", got, tc.H)
			}
		})
	}
}
