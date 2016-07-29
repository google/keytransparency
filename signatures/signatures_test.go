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
	"testing"
)

func TestNewSigner(t *testing.T) {
	tests := []struct {
		pem string
	}{
		{ // openssl ecparam -name prime256v1 -genkey -out p256-key.pem
			`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`,
		},
	}
	for _, tc := range tests {
		k, rest, err := PrivateKeyFromPEM([]byte(tc.pem))
		if err != nil {
			t.Errorf("PrivateKeyFromPEM(): %v", err)
		}
		if len(rest) > 0 {
			t.Errorf("Data left after parsing: %v", rest)
		}
		if _, err := NewSignatureSigner(rand.Reader, k); err != nil {
			t.Errorf("NewSigantureSigner(): %v", err)
		}
	}
}

func TestNewVerifier(t *testing.T) {
	tests := []struct {
		pem string
	}{
		// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
		// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
		{`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`,
		},
	}
	for _, tc := range tests {
		k, rest, err := PublicKeyFromPEM([]byte(tc.pem))
		if err != nil {
			t.Errorf("PublicKeyFromPEM(): %v", err)
		}
		if len(rest) > 0 {
			t.Errorf("Data left after parsing: %v", rest)
		}
		if _, err := NewSignatureVerifier(k); err != nil {
			t.Errorf("NewSigantureVerifier(): %v", err)
		}
	}
}

func TestSignVerifier(t *testing.T) {
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	priv := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	pub := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`

	ka, _, _ := PrivateKeyFromPEM([]byte(priv))
	signer, err := NewSignatureSigner(rand.Reader, ka)
	if err != nil {
		t.Fatalf("NewSigantureSigner(): %v", err)
	}
	kb, _, _ := PublicKeyFromPEM([]byte(pub))
	verifier, err := NewSignatureVerifier(kb)
	if err != nil {
		t.Fatalf("NewSigantureVerifier(): %v", err)
	}

	tests := []struct {
		data interface{}
	}{
		{struct{ Foo string }{"bar"}},
	}
	for _, tc := range tests {
		sig, err := signer.Sign(tc.data)
		if err != nil {
			t.Errorf("Sign(%v): %v", tc.data, err)
		}
		if err := verifier.Verify(tc.data, sig); err != nil {
			t.Errorf("Verify(%v, %v): %v", tc.data, sig, err)
		}
	}
}

func TestConsistentName(t *testing.T) {
	// Verify that the ID generated from from pub and from priv are the same.

	tests := []struct {
		priv string
		pub  string
	}{
		{
			// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
			`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`,
			// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
			`-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`},
	}
	for _, tc := range tests {
		ka, _, _ := PrivateKeyFromPEM([]byte(tc.priv))
		kb, _, _ := PublicKeyFromPEM([]byte(tc.pub))

		signer, err := NewSignatureSigner(rand.Reader, ka)
		if err != nil {
			t.Fatalf("NewSigantureSigner(): %v", err)
		}
		verifier, err := NewSignatureVerifier(kb)
		if err != nil {
			t.Fatalf("NewSigantureVerifier(): %v", err)
		}

		if got, want := signer.KeyName, verifier.KeyName; got != want {
			t.Errorf("Signer.Name: %v, want %v", got, want)
		}
	}
}
