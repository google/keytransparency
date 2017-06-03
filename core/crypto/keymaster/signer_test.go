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

	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGbhE2+z8d5lHzb0gmkS78d86gm5gHUtXCpXveFbK3pcoAoGCCqGSM49
AwEHoUQDQgAEUxX42oxJ5voiNfbjoz8UgsGqh1bD1NXK9m8VivPmQSoYUdVFgNav
csFaQhohkiCEthY51Ga6Xa+ggn+eTZtf9Q==
-----END EC PRIVATE KEY-----`
)

func TestSignerFromPEM(t *testing.T) {
	signatures.Rand = dev.Zeros
	for _, priv := range []string{
		testPrivKey,
	} {
		_, err := NewSignerFromPEM([]byte(priv))
		if err != nil {
			t.Errorf("SignerFromPEM(): %v", err)
		}
	}
}

func TestSignerFromKey(t *testing.T) {
	signatures.Rand = dev.Zeros
	for _, priv := range []string{
		testPrivKey,
	} {
		p, _ := pem.Decode([]byte(priv))
		if p == nil {
			t.Error("pem.Decode() failed")
		}
		if _, err := NewSignerFromRawKey(p.Bytes); err != nil {
			t.Errorf("SignerFromRawKey(): %v", err)
		}
	}
}
