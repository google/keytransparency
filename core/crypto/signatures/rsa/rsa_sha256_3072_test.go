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

package rsa

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math"
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/crypto/signatures"
)

const (
	// openssl genrsa -out rsa-key.pem 1024
	testPrivKey1024 = `-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC+ANWF2E0kc+eLC4VFRH5uLJC3dZfzK3v6FRawzCP75w5O6oKb
TaQNz3JyTiRiS3O1UR6xD4wBKx4yUyp3uGgtBEb8UKylNg9moT9ZcKQhJF3QvB9S
oXSuTEdeCD9ZtSjaJoOFqScjQfgHQLRZ55ZgO5ZKMUnKydt3cUMLLC2jUQIDAQAB
AoGBAIUBZndkfFP5Quvl66waj3qmfcO/cNgL56Sf4Jtwu/vZuf1qUnVO+3mjb1Uu
+G9KrDwQBjEiVfp3aZMG/uKB14H+Z+MU91cCPhK6S3QXjBASdylUvVJJNOi2BuE9
tzoVpnBiEM3GPKLi6m/z5MAEk5jb4OEzxaZUnt/UlXA6A+ixAkEA6vez+7B1cQ8o
5s2qxpO/VTwZLXxIcsFsdeINd7Ear8LtdVt7nffMycHei6Tv0sM7l4oxbneNWGq9
v9LBNs8WjQJBAM8CxULMDW6DkHOotLO3fhpg6cjYYVMSCrecx5/v/pw4hNCfK6Wl
fD/mjEQor/Q6Tmk76wXHNR8jQmX7hR3XYNUCQFz4M5vTvzRD5lAkcnzt+tez1tZ7
hYL6a3rdPaztQ3zl6OT1lJz1bm8qKW8hjM7c9thIErT90sx4N6oNruuL1wUCQFKk
1IPaWvJn69+A1sN42gtF7Y+VcyVq6oRrPvcHJSrRFZUENrSm4HfSXuVHKRfjvzIc
DbP816Rau0Njqr1DIxECQCtKg4WnEbkDYw4WTUbWyGlOCshVaNr01ajv2osXDJke
gE2k8L3WgOjnoLgdQbhZ7XI2SySpBaac8s4HTCocGoY=
-----END RSA PRIVATE KEY-----`
	// openssl rsa -in rsa-key.pem -pubout -out rsa-pubkey.pem
	testPubKey1024 = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+ANWF2E0kc+eLC4VFRH5uLJC3
dZfzK3v6FRawzCP75w5O6oKbTaQNz3JyTiRiS3O1UR6xD4wBKx4yUyp3uGgtBEb8
UKylNg9moT9ZcKQhJF3QvB9SoXSuTEdeCD9ZtSjaJoOFqScjQfgHQLRZ55ZgO5ZK
MUnKydt3cUMLLC2jUQIDAQAB
-----END PUBLIC KEY-----`
	// openssl genrsa -out rsa-key.pem 3072
	testPrivKey3072 = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
	// openssl rsa -in rsa-key.pem -pubout -out rsa-pubkey.pem
	testPubKey3072 = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAyTFh7p5YqZr3W9UsE1XY
HyUCydqEQc/iGA7B8ovxc9quxEPtqpQajhvmYaf4yjTeCIt8eQWaAmmyShQ3peox
0al6/Yl50E6pBCXyxUzurcSXGZa6rxlTifzfHksLczk/g2YJ/vm4ROpKr+Uy78+l
Vvfq8/FGYuhILDFkaQm/mD6lFfOrEEtWGfdPIdcsUhhOeQF8wDgMmgx3X+fQaw/N
qM7U4+ADEHJTmFVRFGtbNs4V4/L6M0OudVGGqUhriymLFErpKql7AQ8aFT2qjcZQ
kPgBbvJ3tirFVz7UO8KGgdsdi/VvnFRn/JxAZkrQVnJ1e8HDsbIZ0xnK4cIYfuIA
Q2YwgTL2awIEzqWaS1LtjeK2y7BrLNWeokMji8tck56XgxQAYm5fFVlDMY5VVKyR
WTgpyJfHEaaUPSFhl6vifbMfK+WK6Ho8XD3b6poMqryiqOBcBSjAkNceapL3NiVy
OXB+JeTEob8mAQXdmT0Rd5gbvm5W47XYLKycj4XQMIWnAgMBAAE=
-----END PUBLIC KEY-----`
)

func newSigner(t *testing.T, pemKey []byte) signatures.Signer {
	p, _ := pem.Decode(pemKey)
	if p == nil {
		t.Fatalf("no PEM block found")
	}
	k, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PrivateKey failed: %v", err)
	}
	signer, err := NewSigner(k)
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
	verifier, err := NewVerifier(k.(*rsa.PublicKey))
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
		{testPrivKey3072, testPubKey3072},
	} {
		signer := newSigner(t, []byte(tc.priv))
		verifier := newVerifier(t, []byte(tc.pub))

		if got, want := signer.KeyID(), verifier.KeyID(); got != want {
			t.Errorf("signer.KeyID(): %v, want %v", got, want)
		}
	}
}

func TestSignerWrongKeySize(t *testing.T) {
	// Signer
	p, _ := pem.Decode([]byte(testPrivKey1024))
	if p == nil {
		t.Fatalf("no PEM block found")
	}
	k, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKCS1PrivateKey failed: %v", err)
	}
	_, err = NewSigner(k)
	if got, want := err, signatures.ErrWrongKeyType; got != want {
		t.Errorf("NewSigner with key size 1024 returned %v, want %v", got, want)
	}
}

func TestVerifierWrongKeySize(t *testing.T) {
	// Verifier
	p, _ := pem.Decode([]byte(testPubKey1024))
	if p == nil {
		t.Fatalf("no PEM block found")
	}
	k, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		t.Fatalf("x509.ParsePKIXPublicKey failed: %v", err)
	}
	_, err = NewVerifier(k.(*rsa.PublicKey))
	if got, want := err, signatures.ErrWrongKeyType; got != want {
		t.Errorf("NewVerifier with key size 1024 returned %v, want %v", got, want)
	}
}

type env struct {
	signer   signatures.Signer
	verifier signatures.Verifier
}

func newEnv(t *testing.T) *env {
	signer := newSigner(t, []byte(testPrivKey3072))
	verifier := newVerifier(t, []byte(testPubKey3072))
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
	pkBytes, _ := pem.Decode([]byte(testPubKey3072))
	if pkBytes == nil {
		t.Fatalf("pem.Decode could not find a PEM block")
	}
	if got, want := sPK.GetDer(), pkBytes.Bytes; !bytes.Equal(got, want) {
		t.Errorf("sPK.GetRsaVerifyingSha256_3072()=%v, want %v", got, want)
	}
	if got, want := vPK.GetDer(), pkBytes.Bytes; !bytes.Equal(got, want) {
		t.Errorf("vPK.GetRsaVerifyingSha256_3072()=%v, want %v", got, want)
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
	skPEM, pkPEM, err := GeneratePEMs()
	if err != nil {
		t.Fatalf("GeneratePEMs failed: %v", err)
	}

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
