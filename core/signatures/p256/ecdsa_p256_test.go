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

package p256

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/google/key-transparency/core/signatures"

	kmpb "github.com/google/key-transparency/core/proto/keymaster"
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

// DevZero is an io.Reader that returns 0's
type DevZero struct{}

// Read returns 0's
func (DevZero) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

func newSigner(t *testing.T, pemKey []byte) signatures.Signer {
	signatures.Rand = DevZero{}
	p, _ := pem.Decode(pemKey)
	if p == nil {
		t.Fatalf("no PEM block found")
	}
	k, err := x509.ParseECPrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseECPrivateKey failed: %v", err)
	}
	signer, err := NewSigner(k, time.Now(), "test_description", kmpb.SigningKey_ACTIVE)
	if err != nil {
		t.Fatalf("NewSigner failed: %v", err)
	}
	return signer
}

func newVerifier(t *testing.T, pemKey []byte) signatures.Verifier {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		t.Fatalf("no PEM block found")
	}
	k, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey failed: %v", err)
	}
	verifier, err := NewVerifier(k.(*ecdsa.PublicKey), time.Now(), "test_description", kmpb.VerifyingKey_ACTIVE)
	if err != nil {
		t.Fatalf("NewVerifier failed: %v", err)
	}
	return verifier
}

func TestConsistentKeyIDs(t *testing.T) {
	// Verify that the ID generated from from pub and from priv are the same.
	for _, tc := range []struct {
		priv string
		pub  string
	}{
		{testPrivKey, testPubKey},
	} {
		signer := newSigner(t, []byte(tc.priv))
		verifier := newVerifier(t, []byte(tc.pub))

		if got, want := signer.KeyID(), verifier.KeyID(); got != want {
			t.Errorf("signer.KeyID(): %v, want %v", got, want)
		}
	}
}

type env struct {
	signer   signatures.Signer
	verifier signatures.Verifier
}

func newEnv(t *testing.T) *env {
	signer := newSigner(t, []byte(testPrivKey))
	verifier := newVerifier(t, []byte(testPubKey))
	return &env{signer, verifier}
}

func TestSignVerifier(t *testing.T) {
	e := newEnv(t)
	for _, tc := range []struct {
		data interface{}
	}{
		{struct{ Foo string }{"bar"}},
	} {
		sig, err := e.signer.Sign(tc.data)
		if err != nil {
			t.Errorf("Sign(%v): %v", tc.data, err)
		}
		if err := e.verifier.Verify(tc.data, sig); err != nil {
			t.Errorf("Verify(%v, %v): %v", tc.data, sig, err)
		}
	}
}

func TestPublicKey(t *testing.T) {
	e := newEnv(t)

	// Make sure that signer and verifier both return the same PublicKey.
	sPK, err := e.signer.PublicKey()
	if err != nil {
		t.Fatalf("signer.PublicKey() failed: %v", err)
	}
	vPK, err := e.verifier.PublicKey()
	if err != nil {
		t.Fatalf("verifier.PublicKey() failed: %v", err)
	}
	if !reflect.DeepEqual(sPK, vPK) {
		t.Error("signer.PublicKey() and verifier.PublicKey() should be equal")
	}

	// Make sure that the returned PublicKey contains the correct byte slice.
	pkBytes, _ := pem.Decode([]byte(testPubKey))
	if pkBytes == nil {
		t.Fatalf("pem.Decode could not find a PEM block")
	}
	if got, want := sPK.GetEcdsaVerifyingP256(), pkBytes.Bytes; !reflect.DeepEqual(got, want) {
		t.Errorf("sPK.GetEcdsaVerifyingP256()=%v, want %v", got, want)
	}
	if got, want := vPK.GetEcdsaVerifyingP256(), pkBytes.Bytes; !reflect.DeepEqual(got, want) {
		t.Errorf("vPK.GetEcdsaVerifyingP256()=%v, want %v", got, want)
	}
}

func TestRightTruncateSignature(t *testing.T) {
	e := newEnv(t)
	data := struct{ Foo string }{"bar"}

	// Truncate bytes from the end of sig and try to verify.
	sig, err := e.signer.Sign(data)
	if err != nil {
		t.Errorf("Sign(%v): %v", data, err)
	}
	sigLen := len(sig.Signature)
	for i := 0; i < sigLen; i++ {
		sig.Signature = sig.Signature[:len(sig.Signature)-1]
		if err := e.verifier.Verify(data, sig); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the end of the signature", i)
		}
	}
}

func TestLeftTruncateSignature(t *testing.T) {
	e := newEnv(t)
	data := struct{ Foo string }{"bar"}

	// Truncate bytes from the beginning of sig and try to verify.
	sig, err := e.signer.Sign(data)
	if err != nil {
		t.Errorf("Sign(%v): %v", data, err)
	}
	sigLen := len(sig.Signature)
	for i := 0; i < sigLen; i++ {
		sig.Signature = sig.Signature[1:]
		if err := e.verifier.Verify(data, sig); err == nil {
			t.Errorf("Verify unexpectedly succeeded after truncating %v bytes from the beginning of the signature", i)
		}
	}
}

func TestBitFlipSignature(t *testing.T) {
	e := newEnv(t)
	data := struct{ Foo string }{"bar"}

	// Truncate bytes from the beginning of sig and try to verify.
	sig, err := e.signer.Sign(data)
	if err != nil {
		t.Errorf("Sign(%v): %v", data, err)
	}
	for i := 0; i < len(sig.Signature)*8; i++ {
		// Flip bit in position i.
		flippedSig := *sig
		flippedSig.Signature = flipBit(sig.Signature, uint(i))

		// Verify signature
		if err := e.verifier.Verify(data, &flippedSig); err == nil {
			t.Errorf("Verify unexpectedly succeeded after flipping bit %v of the signature", i)
		}
	}
}

func flipBit(a []byte, pos uint) []byte {
	index := int(math.Floor(float64(pos) / 8))
	b := byte(a[index])
	b ^= (1 << uint(math.Mod(float64(pos), 8.0)))

	var buf bytes.Buffer
	buf.Write(a[:index])
	buf.Write([]byte{b})
	buf.Write(a[index+1:])
	return buf.Bytes()
}

func TestGeneratePEMs(t *testing.T) {
	signatures.Rand = DevZero{}
	skPEM, pkPEM, err := GeneratePEMs()

	// Ensure that the generated keys are valid.
	signer := newSigner(t, skPEM)
	verifier := newVerifier(t, pkPEM)
	data := struct{ Foo string }{"bar"}
	sig, err := signer.Sign(data)
	if err != nil {
		t.Fatalf("signer.Sign(%v) failed: %v", data, err)
	}
	if err := verifier.Verify(data, sig); err != nil {
		t.Errorf("verifier.Verify() failed: %v", err)
	}
}
