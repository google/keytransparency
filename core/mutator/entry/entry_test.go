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

package entry

import (
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"

	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/crypto/keyspb"

	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

const (
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey1 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIBoLpoKGPbrFbEzF/ZktBSuGP+Llmx2wVKSkbdAdQ+3JoAoGCCqGSM49
AwEHoUQDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4hnGbXDPbdFlL1nmayhnqyEfR
dXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey1 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+xVOdphkfpEtl7OF8oCyvWw31dV4
hnGbXDPbdFlL1nmayhnqyEfRdXNlpBT2U9hXcSxliKI1rHrAJFDx3ncttA==
-----END PUBLIC KEY-----`
	// openssl ecparam -name prime256v1 -genkey -out p256-key.pem
	testPrivKey2 = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGugtYzUjyysX/JtjAFA6K3SzgBSmNjog/3e//VWRLQQoAoGCCqGSM49
AwEHoUQDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQbLOA+tLe/MbwZ69SRdG6Rx92f
9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END EC PRIVATE KEY-----`
	// openssl ec -in p256-key.pem -pubout -out p256-pubkey.pem
	testPubKey2 = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJKDbR4uyhSMXW80x02NtYRUFlMQb
LOA+tLe/MbwZ69SRdG6Rx92f9tbC6dz7UVsyI7vIjS+961sELA6FeR91lA==
-----END PUBLIC KEY-----`
)

func mustPublicKey(pubPEM string) *keyspb.PublicKey {
	pubKey, err := pem.UnmarshalPublicKey(pubPEM)
	if err != nil {
		panic(err)
	}
	p, err := der.ToPublicProto(pubKey)
	if err != nil {
		panic(err)
	}
	return p
}

func mustPublicKeys(pubPEMs []string) []*keyspb.PublicKey {
	authKeys := make([]*keyspb.PublicKey, len(pubPEMs))
	for i, key := range pubPEMs {
		authKeys[i] = mustPublicKey(key)
	}
	return authKeys
}

func signersFromPEMs(t *testing.T, keys [][]byte) []signatures.Signer {
	signatures.Rand = dev.Zeros
	signers := make([]signatures.Signer, 0, len(keys))
	for _, key := range keys {
		signer, err := factory.NewSignerFromPEM(key)
		if err != nil {
			t.Fatalf("NewSigner(): %v", err)
		}
		signers = append(signers, signer)
	}
	return signers
}

func TestFromLeafValue(t *testing.T) {
	entry := &tpb.Entry{Commitment: []byte{1, 2}}
	entryB, _ := proto.Marshal(entry)
	for i, tc := range []struct {
		leafVal []byte
		want    *tpb.Entry
		wantErr bool
	}{
		{[]byte{}, &tpb.Entry{}, false},          // empty leaf bytes -> return 'empty' proto, no error
		{nil, nil, false},                        // non-existing leaf -> return nil, no error
		{[]byte{2, 2, 2, 2, 2, 2, 2}, nil, true}, // no valid proto Message
		{entryB, entry, false},                   // valid leaf
	} {
		if got, _ := FromLeafValue(tc.leafVal); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("FromLeafValue(%v)=%v, _ , want %v", tc.leafVal, got, tc.want)
			t.Error(i)
		}
		if _, gotErr := FromLeafValue(tc.leafVal); (gotErr != nil) != tc.wantErr {
			t.Errorf("FromLeafValue(%v)=_, %v", tc.leafVal, gotErr)
		}
	}
}
