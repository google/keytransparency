// Copyright 2019 Google Inc. All Rights Reserved.
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

package tinkio

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/testutil"
	"github.com/google/trillian/crypto/keys/pem"

	commonpb "github.com/google/tink/go/proto/common_go_proto"
	ecdsapb "github.com/google/tink/go/proto/ecdsa_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
)

const (
	outputPrefix = tinkpb.OutputPrefixType_RAW
	hashType     = commonpb.HashType_SHA256
)

// ECDSAPEMKeyset converts a set of PEMs into a tink.Keyset.
// Implements tink.KeysetReader.
type ECDSAPEMKeyset struct {
	PEMs     []string
	Password string
}

// Read returns a (cleartext) Keyset object from a set of PEMs.
func (p *ECDSAPEMKeyset) Read() (*tinkpb.Keyset, error) {
	keysetKeys := make([]*tinkpb.Keyset_Key, 0, len(p.PEMs))
	var primaryKeyID uint32
	for i, pem := range p.PEMs {
		if pem == "" {
			continue // Skip this keyID.
		}
		keyData, err := keyDataFromPEM(pem, p.Password)
		if err != nil {
			return nil, err
		}
		keyID := uint32(i + 1)
		primaryKeyID = keyID
		keysetKeys = append(keysetKeys,
			testutil.NewKey(keyData, tinkpb.KeyStatusType_ENABLED, keyID, outputPrefix))
	}
	ks := testutil.NewKeyset(primaryKeyID, keysetKeys)
	if err := keyset.Validate(ks); err != nil {
		return nil, fmt.Errorf("tink.ValidateKeyset(): %v", err)
	}
	return ks, nil
}

// ReadEncrypted returns an EncryptedKeyset object from disk.
func (p *ECDSAPEMKeyset) ReadEncrypted() (*tinkpb.EncryptedKeyset, error) {
	return nil, errors.New("tinkio: Unimplemented")
}

// keyDataFromPEM returns tinkpb.KeyData for both public and private key PEMs.
// Only ecdsa keys, however, are supported by Tink.
func keyDataFromPEM(pem, password string) (*tinkpb.KeyData, error) {
	key, err := unmarshalPEM(pem, password)
	if err != nil {
		return nil, err
	}

	switch t := key.(type) {
	case *ecdsa.PrivateKey:
		return privKeyData(t)
	case *ecdsa.PublicKey:
		return pubKeyData(t)
	default:
		return nil, fmt.Errorf("unknown key type: %T", key)
	}
}

// unmarshalPEM returns a go native public or private key.
func unmarshalPEM(pemData, password string) (interface{}, error) {
	signer, err := pem.UnmarshalPrivateKey(pemData, password)
	if err == nil {
		return signer, nil
	}
	pubKey, err := pem.UnmarshalPublicKey(pemData)
	if err == nil {
		return pubKey, nil
	}
	return nil, err
}

// privKeyData produces tinkpb.KeyData from a private key.
func privKeyData(priv *ecdsa.PrivateKey) (*tinkpb.KeyData, error) {
	privKey := testutil.NewECDSAPrivateKey(
		testutil.ECDSASignerKeyVersion,
		ecdsaPubKeyPB(&priv.PublicKey),
		priv.D.Bytes())
	serializedKey, err := proto.Marshal(privKey)
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal(): %v", err)
	}
	return testutil.NewKeyData(testutil.ECDSASignerTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PRIVATE), nil
}

// pubKeyData produces tinkpb.KeyData from a public key.
func pubKeyData(pub *ecdsa.PublicKey) (*tinkpb.KeyData, error) {
	serializedKey, err := proto.Marshal(ecdsaPubKeyPB(pub))
	if err != nil {
		return nil, fmt.Errorf("proto.Marshal(): %v", err)
	}
	return testutil.NewKeyData(testutil.ECDSAVerifierTypeURL,
		serializedKey,
		tinkpb.KeyData_ASYMMETRIC_PUBLIC), nil
}

// ecdsaPubKeyPB returns a tink ecdsapb.EcdsaPublicKey
func ecdsaPubKeyPB(pub *ecdsa.PublicKey) *ecdsapb.EcdsaPublicKey {
	return testutil.NewECDSAPublicKey(
		testutil.ECDSAVerifierKeyVersion,
		testutil.NewECDSAParams(
			hashType,
			tinkCurve(pub.Curve),
			ecdsapb.EcdsaSignatureEncoding_DER),
		pub.X.Bytes(),
		pub.Y.Bytes())
}

// tinkCurve maps between elliptic.Curve and commonpb.EllipticCurveType.
func tinkCurve(curve elliptic.Curve) commonpb.EllipticCurveType {
	switch curve {
	case elliptic.P256():
		return commonpb.EllipticCurveType_NIST_P256
	case elliptic.P384():
		return commonpb.EllipticCurveType_NIST_P384
	case elliptic.P521():
		return commonpb.EllipticCurveType_NIST_P521
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE
	}
}
