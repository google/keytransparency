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
	"crypto/ecdsa"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"
	"github.com/google/trillian/crypto/keys/pem"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	commonpb "github.com/google/tink/proto/common_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_proto"
	tinkpb "github.com/google/tink/proto/tink_proto"
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

func mustPrivateKey(privPEM string, keyID uint32) *tinkpb.Keyset_Key {
	signer, err := pem.UnmarshalPrivateKey(privPEM, "")
	if err != nil {
		panic(err)
	}

	priv, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		panic("not ecdsa private key")
	}

	params := signature.NewEcdsaParams(
		commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)

	publicKey := signature.NewEcdsaPublicKey(
		signature.ECDSA_VERIFY_KEY_VERSION,
		params, priv.X.Bytes(), priv.Y.Bytes())
	privKey := signature.NewEcdsaPrivateKey(
		signature.ECDSA_SIGN_KEY_VERSION,
		publicKey, priv.D.Bytes())
	serializedKey, _ := proto.Marshal(privKey)
	keyData := tink.NewKeyData(signature.ECDSA_SIGN_TYPE_URL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	return tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
}

func mustPublicKey(pubPEM string, keyID uint32) *tinkpb.Keyset_Key {
	pubKey, err := pem.UnmarshalPublicKey(pubPEM)
	if err != nil {
		panic(err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		panic(fmt.Sprintf("not ecdsa public key: %T", pubKey))
	}

	params := signature.NewEcdsaParams(
		commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := signature.NewEcdsaPublicKey(
		signature.ECDSA_VERIFY_KEY_VERSION,
		params, pub.X.Bytes(), pub.Y.Bytes())
	serializedKey, _ := proto.Marshal(publicKey)
	keyData := tink.NewKeyData(signature.ECDSA_VERIFY_TYPE_URL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	return tink.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
}

func mustPublicKeys(pubPEMs []string) *tink.KeysetHandle {
	keys := make([]*tinkpb.Keyset_Key, 0, len(pubPEMs))
	for i, pem := range pubPEMs {
		keysetKey := mustPublicKey(pem, uint32(i+1))
		keys = append(keys, keysetKey)
	}
	keyset := tink.NewKeyset(1, keys)
	parsedHandle, err := tink.CleartextKeysetHandle().ParseKeyset(keyset)
	if err != nil {
		panic(fmt.Sprintf("ParseKeyset(): %v", err))
	}
	return parsedHandle
}

func mustPrivateKeys(privPEMs []string) []*tink.KeysetHandle {
	handles := make([]*tink.KeysetHandle, 0, len(privPEMs))
	for _, pem := range privPEMs {
		keysetKey := mustPrivateKey(pem, 1)
		keyset := tink.NewKeyset(1, []*tinkpb.Keyset_Key{keysetKey})
		parsedHandle, err := tink.CleartextKeysetHandle().ParseKeyset(keyset)
		if err != nil {
			panic(fmt.Sprintf("ParseKeyset(): %v", err))
		}
		handles = append(handles, parsedHandle)
	}
	return handles
}

func TestFromLeafValue(t *testing.T) {
	signature.PublicKeyVerifyConfig().RegisterStandardKeyTypes()
	entry := &pb.Entry{Commitment: []byte{1, 2}}
	entryB, _ := proto.Marshal(entry)
	for i, tc := range []struct {
		leafVal []byte
		want    *pb.Entry
		wantErr bool
	}{
		{[]byte{}, &pb.Entry{}, false},           // empty leaf bytes -> return 'empty' proto, no error
		{nil, nil, false},                        // non-existing leaf -> return nil, no error
		{[]byte{2, 2, 2, 2, 2, 2, 2}, nil, true}, // no valid proto Message
		{entryB, entry, false},                   // valid leaf
	} {
		if got, _ := FromLeafValue(tc.leafVal); !proto.Equal(got, tc.want) {
			t.Errorf("FromLeafValue(%v)=%v, _ , want %v", tc.leafVal, got, tc.want)
			t.Error(i)
		}
		if _, gotErr := FromLeafValue(tc.leafVal); (gotErr != nil) != tc.wantErr {
			t.Errorf("FromLeafValue(%v)=_, %v", tc.leafVal, gotErr)
		}
	}
}
