// Copyright 2016 Google Inc. All Rights Reserved.
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

package integration

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/key-transparency/authentication"
	"github.com/google/key-transparency/client"

	"golang.org/x/net/context"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

var (
	defaultUserID = "e2eshare.test@gmail.com"
	// Generated test key in End to End app and exported it.
	defaultKeyring = `
9852040000000013082a8648ce3d0301070203044d0c9630a2ffe1d3f5d4
54400b9f22dfe0f7cc3f76c6a493832ed92421748065a0bbacabab13a17f
877afc52af5332264ee25bd804b5184723100df62274068ab4193c653265
73686172652e7465737440676d61696c2e636f6d3e888d04131308003fff
0000000502558c236cff000000021b03ff000000028b09ff000000059508
090a0bff00000003960102ff000000029e01ff00000009904b20db14afb2
81e3000046840100dd5250123def89ec4ec1656308fb59697ef1d0b07d53
bfab9b9249fd6a427dd500ff786dc7dd42151fa295fdf5d67edee912f6b9
8ba26cc7a8a43bade455615b61a2b856040000000012082a8648ce3d0301
070203045a522d5816d914a06bf094485ddad969efd2475ec9b097741fc6
d4afafd8b6936fa6cdb4dbb7f43943b5ff170e6e6ee647cb41c2f92c5843
a037b96863f4da2503010807886d04181308001fff0000000582558c236c
ff000000029b0cff00000009904b20db14afb281e30000b3370100b5012d
97d8cace51987a783862c916002c839db6b9a3fac6c1ca058d17f5062c01
00f167d12ad2e96494a54d3e07ef24f8f5c3a4528c647658a3f13aaad56b
a5d613`
	defaultASCIIArmor = `-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEAAAAABMIKoZIzj0DAQcCAwRNDJYwov/h0/XUVEALnyLf4PfMP3bGpJODLtkk
IXSAZaC7rKurE6F/h3r8Uq9TMiZO4lvYBLUYRyMQDfYidAaKtBk8ZTJlc2hhcmUu
dGVzdEBnbWFpbC5jb20+iI0EExMIAD//AAAABQJVjCNs/wAAAAIbA/8AAAACiwn/
AAAABZUICQoL/wAAAAOWAQL/AAAAAp4B/wAAAAmQSyDbFK+ygeMAAEaEAQDdUlAS
Pe+J7E7BZWMI+1lpfvHQsH1Tv6ubkkn9akJ91QD/eG3H3UIVH6KV/fXWft7pEva5
i6Jsx6ikO63kVWFbYaK4VgQAAAAAEggqhkjOPQMBBwIDBFpSLVgW2RSga/CUSF3a
2Wnv0kdeybCXdB/G1K+v2LaTb6bNtNu39DlDtf8XDm5u5kfLQcL5LFhDoDe5aGP0
2iUDAQgHiG0EGBMIAB//AAAABYJVjCNs/wAAAAKbDP8AAAAJkEsg2xSvsoHjAACz
NwEAtQEtl9jKzlGYeng4YskWACyDnba5o/rGwcoFjRf1BiwBAPFn0SrS6WSUpU0+
B+8k+PXDpFKMZHZYo/E6qtVrpdYT
=+kV0
-----END PGP PUBLIC KEY BLOCK-----`
)

func CreateDefaultUser(env *Env, t testing.TB) {
	authCtx := authentication.NewFake().NewContext(defaultUserID)
	keyring, _ := hex.DecodeString(strings.Replace(defaultKeyring, "\n", "", -1))
	profile := &pb.Profile{map[string][]byte{"pgp": keyring}}
	_, err := env.Client.Update(authCtx, defaultUserID, profile)
	if got, want := err, client.ErrRetry; got != want {
		t.Fatalf("Update(%v): %v, want %v", defaultUserID, got, want)
	}
	if err := env.Signer.Sequence(); err != nil {
		t.Fatalf("Failed to sequence: %v", err)
	}
	if err := env.Signer.CreateEpoch(); err != nil {
		t.Fatalf("Failed to CreateEpoch: %v", err)
	}
}

func TestHkpLookup(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)

	CreateDefaultUser(env, t)

	var tests = []struct {
		op              string
		userID          string
		options         string
		wantBody        string
		wantContentType string
		want            bool
	}{
		// This should return keys.
		{"get", defaultUserID, "", defaultASCIIArmor, "text/plain", true},
		{"get", defaultUserID, "mr", defaultASCIIArmor, "application/pgp-keys", true},
		// Looking up non-existing user.
		{"get", "nobody", "", "", "", false},
		// Unimplemented operations.
		{"index", defaultUserID, "", "", "", false},
		{"vindex", defaultUserID, "", "", "", false},
		{"index", "", "", "", "", false},
		{"vindex", "", "", "", "", false},
	}

	for _, tc := range tests {
		req := &pb.HkpLookupRequest{
			Op:      tc.op,
			Search:  tc.userID,
			Options: tc.options,
		}
		resp, err := env.Cli.HkpLookup(context.Background(), req)
		if got := err == nil; got != tc.want {
			t.Errorf("HkpLookup(%v): %v, want %v", req, err, tc.want)
		}
		if wantResp := tc.wantBody != "" || tc.wantContentType != ""; wantResp {
			if resp == nil {
				t.Fatalf("HkpLookup(%v): %v, want not nil", req, resp)
			}
			if got := resp.ContentType; got != tc.wantContentType {
				t.Errorf("HkpLookup(%v).ContentType: %v, want %v", req, got, tc.wantContentType)
			}
			if got := string(resp.Body); got != tc.wantBody {
				t.Errorf("HkpLookup(%v).Body: %v, want %v", req, got, tc.wantBody)
			}
		}
	}
}
