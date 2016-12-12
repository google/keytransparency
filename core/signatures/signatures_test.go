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

package signatures

import (
	"crypto/rand"
	"encoding/pem"
	"testing"

	ctmappb "github.com/google/key-transparency/core/proto/ctmap"
	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`
)

func TestGeneratePEMKeyPair(t *testing.T) {
	data := struct{ Foo string }{"bar"}
	for _, tc := range []struct {
		algorithm ctmappb.DigitallySigned_SignatureAlgorithm
		err       error
	}{
		{ctmappb.DigitallySigned_ECDSA, nil},
		{ctmappb.DigitallySigned_ANONYMOUS, ErrUnimplemented},
	} {
		skPEM, pkPEM, err := GeneratePEMKeyPair(tc.algorithm, rand.Reader)
		if got, want := err, tc.err; got != want {
			t.Errorf("GenerateKeyPair(%v)=%v, want %v", tc.algorithm, got, want)
		}
		if err != nil {
			continue
		}

		// Ensure that the generated keys are valid.
		signer, err := SignerFromPEM(rand.Reader, skPEM)
		if err != nil {
			t.Errorf("SignerFromPEM failed: %v", err)
			continue
		}
		verifier, err := VerifierFromPEM(pkPEM)
		if err != nil {
			t.Errorf("VerifierFromPEM failed: %v", err)
			continue
		}
		sig, err := signer.Sign(data)
		if err != nil {
			t.Errorf("signer.Sign(%v) failed: %v", data, err)
		}
		if err := verifier.Verify(data, sig); err != nil {
			t.Errorf("verifier.Verify() failed: %v", err)
		}
	}
}

func TestSignerFromPEM(t *testing.T) {
	for _, priv := range []string{
		testPrivKey,
	} {
		_, err := SignerFromPEM(rand.Reader, []byte(priv))
		if err != nil {
			t.Errorf("SignerFromPEM(): %v", err)
		}
	}
}

func TestVerifierFromPEM(t *testing.T) {
	for _, pub := range []string{
		testPubKey,
	} {
		if _, err := VerifierFromPEM([]byte(pub)); err != nil {
			t.Errorf("VerifierFromPEM(): %v", err)
		}
	}
}

func TestVerifierFromKey(t *testing.T) {
	for _, pub := range []string{
		testPubKey,
	} {
		p, _ := pem.Decode([]byte(pub))
		if p == nil {
			t.Error("pem.Decode() failed")
		}
		pk := &tpb.PublicKey{
			KeyType: &tpb.PublicKey_EcdsaVerifyingP256{
				EcdsaVerifyingP256: p.Bytes,
			},
		}
		if _, err := VerifierFromKey(pk); err != nil {
			t.Errorf("VerifierFromKey(): %v", err)
		}
	}
}
