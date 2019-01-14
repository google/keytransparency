// Copyright 2018 Google Inc. All Rights Reserved.
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

// Package testutil provides helper functions for tests.
package testutil

import (
	"crypto/ecdsa"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/testkeysethandle"
	"github.com/google/tink/go/tink"
	"github.com/google/trillian/crypto/keys/pem"

	commonpb "github.com/google/tink/proto/common_go_proto"
	ecdsapb "github.com/google/tink/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

// PrivateKeyFromPEM produces a Keyset_Key from privatePEM.
func PrivateKeyFromPEM(privPEM string, keyID uint32) *tinkpb.Keyset_Key {
	signer, err := pem.UnmarshalPrivateKey(privPEM, "")
	if err != nil {
		panic(err)
	}

	priv, ok := signer.(*ecdsa.PrivateKey)
	if !ok {
		panic(fmt.Sprintf("not ecdsa private key: %T", signer))
	}

	params := signature.NewECDSAParams(
		commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)

	publicKey := signature.NewECDSAPublicKey(
		signature.ECDSAVerifierKeyVersion,
		params, priv.X.Bytes(), priv.Y.Bytes())
	privKey := signature.NewECDSAPrivateKey(
		signature.ECDSASignerKeyVersion,
		publicKey, priv.D.Bytes())
	serializedKey, err := proto.Marshal(privKey)
	if err != nil {
		panic(fmt.Sprintf("proto.Marshal(): %v", err))
	}
	keyData := tink.CreateKeyData(signature.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE)
	return tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
}

// PublicKeyFromPEM produces a Keyset_Key from pubPEM.
func PublicKeyFromPEM(pubPEM string, keyID uint32) *tinkpb.Keyset_Key {
	pubKey, err := pem.UnmarshalPublicKey(pubPEM)
	if err != nil {
		panic(err)
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		panic(fmt.Sprintf("not ecdsa public key: %T", pubKey))
	}

	params := signature.NewECDSAParams(
		commonpb.HashType_SHA256,
		commonpb.EllipticCurveType_NIST_P256,
		ecdsapb.EcdsaSignatureEncoding_DER)
	publicKey := signature.NewECDSAPublicKey(
		signature.ECDSAVerifierKeyVersion,
		params, pub.X.Bytes(), pub.Y.Bytes())
	serializedKey, err := proto.Marshal(publicKey)
	if err != nil {
		panic(fmt.Sprintf("proto.Marshal(): %v", err))
	}
	keyData := tink.CreateKeyData(signature.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC)
	return tink.CreateKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, tinkpb.OutputPrefixType_TINK)
}

// VerifyKeysetFromPEMs produces a Keyset with pubPEMs.
func VerifyKeysetFromPEMs(pubPEMs ...string) *tink.KeysetHandle {
	var primaryKeyID uint32
	keys := make([]*tinkpb.Keyset_Key, 0, len(pubPEMs))
	for i, pem := range pubPEMs {
		if pem == "" {
			continue
		}
		keyID := uint32(i + 1)
		keysetKey := PublicKeyFromPEM(pem, keyID)
		keys = append(keys, keysetKey)
		primaryKeyID = keyID
	}
	keyset := tink.CreateKeyset(primaryKeyID, keys)
	parsedHandle, err := tink.KeysetHandleWithNoSecret(keyset)
	if err != nil {
		panic(fmt.Sprintf("tink.KeysetHandleWithNoSecret(): %v", err))
	}
	if err := tink.ValidateKeyset(keyset); err != nil {
		panic(fmt.Sprintf("tink.ValidateKeyset(): %v", err))
	}
	return parsedHandle
}

// SignKeysetsFromPEMs produces a slice of keysets, each with one private key.
func SignKeysetsFromPEMs(privPEMs ...string) []tink.Signer {
	signers := make([]tink.Signer, 0, len(privPEMs))
	for i, pem := range privPEMs {
		if pem == "" {
			continue
		}
		keysetKey := PrivateKeyFromPEM(pem, uint32(i+1))
		keyset := tink.CreateKeyset(uint32(i+1), []*tinkpb.Keyset_Key{keysetKey})
		parsedHandle, err := testkeysethandle.KeysetHandle(keyset)
		if err != nil {
			panic(fmt.Sprintf("testkeysethandle.KeysetHandle(): %v", err))
		}
		signer, err := signature.NewSigner(parsedHandle)
		if err != nil {
			panic(fmt.Sprintf("testkeysethandle.NewSigner(): %v", err))
		}
		signers = append(signers, signer)
	}
	return signers
}
