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

package keymaster

import (
	"encoding/pem"
	"testing"

	"github.com/google/trillian/crypto/keyspb"
)

const (
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD
1NXK9m8VivPmQSoYUdVFgNavcsFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END PUBLIC KEY-----`
)

func TestVerifierFromPEM(t *testing.T) {
	for _, pub := range []string{
		testPubKey,
	} {
		if _, err := NewVerifierFromPEM([]byte(pub)); err != nil {
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
		pk := &keyspb.PublicKey{Der: p.Bytes}
		if _, err := NewVerifierFromKey(pk); err != nil {
			t.Errorf("VerifierFromKey(): %v", err)
		}
	}
}

func TestVerifierFromRawKey(t *testing.T) {
	for _, pub := range []string{
		testPubKey,
	} {
		p, _ := pem.Decode([]byte(pub))
		if p == nil {
			t.Error("pem.Decode() failed")
		}
		if _, err := NewVerifierFromRawKey(p.Bytes); err != nil {
			t.Errorf("VerifierFromRawKey(): %v", err)
		}
	}
}
