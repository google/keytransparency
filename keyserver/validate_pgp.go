// Copyright 2015 Google Inc. All Rights Reserved.
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

package keyserver

import (
	"io"
	"reflect"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"

	"github.com/google/key-server-transparency/status"
)

// Fingerprint is the type used to identify keys.
type Fingerprint [20]byte

// validatePGP verifies that there is
// - One entity in the key ring.
// - One userID packet that matches the userID arg exactly.
// - One signature with the expected algorithm choices.
// - Signatures are within their valididty periods.
// - TODO(gbelvin) paremeter checks for public key.
// returns fingerprint, error
//
func validatePGP(userID string, key io.Reader) (*Fingerprint, error) {
	// Sets for required options.
	requiredSymmetric := map[uint8]bool{9: true}
	requiredHash := map[uint8]bool{8: true, 9: true, 10: true, 11: true}

	// Verify signatures, check revocation.
	entityList, err := openpgp.ReadKeyRing(key)
	if err != nil {
		return &Fingerprint{}, err
	}
	// Only allow one entity / identity key.
	if got, want := len(entityList), 1; got != want {
		return &Fingerprint{}, status.Errorf(status.InvalidArgument, "len(entitys) = %v, want %v", got, want)
	}
	entity := entityList[0]

	// Only allow one identity / username.
	if got, want := len(entity.Identities), 1; got != want {
		return &Fingerprint{}, status.Errorf(status.InvalidArgument, "len(identities) = %v, want %v", got, want)
	}
	// No revocations allowed.
	if got, want := len(entity.Revocations), 0; want != got {
		return &Fingerprint{}, status.Errorf(status.InvalidArgument, "len(revocations) = %v, want %v", got, want)
	}
	// Verify the UserId.
	for _, id := range entity.Identities {
		if got, want := id.UserId.Id, userID; got != want {
			return &Fingerprint{}, status.Errorf(status.PermissionDenied, "UserId = %v, want %v", got, want)
		}
		if id.SelfSignature == nil {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Missing self signature")
		}
		// Verify timestamps.
		if id.SelfSignature.KeyExpired(time.Now()) {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Signature expired")
		}
		// Verify encryption types. AES-256
		if got, want := id.SelfSignature.PreferredSymmetric, requiredSymmetric; !setEquals(want, got) {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "PreferredSymmetric = %v, want %v", got, want)
		}
		// Verify preferred hash types.
		if got, want := id.SelfSignature.PreferredHash, requiredHash; !setEquals(want, got) {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "PreferredHash = %v, want %v", got, want)
		}
		// Verify that hash is one of the preferred hash types.
		hashID, ok := s2k.HashToHashId(id.SelfSignature.Hash)
		if !ok {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Invalid hash %v", id.SelfSignature.Hash)
		}
		if _, ok := requiredHash[hashID]; !ok {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Hash algo %v not approved", hashID)
		}
		// Verify flags.
		if !id.SelfSignature.FlagCertify || !id.SelfSignature.FlagSign {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Self signature missing certify flag")
		}
		if id.SelfSignature.FlagEncryptCommunications || id.SelfSignature.FlagEncryptStorage {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Self signature has encrypt flag")
		}
		// No extra signatures allowed.
		if got, want := len(id.Signatures), 0; want != got {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "len(id.Sigs) = %v, want %v", got, want)
		}

	}
	// Only allow one subkey.
	if got, want := len(entity.Subkeys), 1; want != got {
		return &Fingerprint{}, status.Errorf(status.InvalidArgument, "len(Subkeys) = %v, want %v", got, want)
	}
	for _, subkey := range entity.Subkeys {
		// Verify expiration.
		if subkey.Sig.KeyExpired(time.Now()) {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Signature expired")
		}
		// Only accept ECC keys.
		if got, want := subkey.PublicKey.PubKeyAlgo, packet.PubKeyAlgoECDH; got != want {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "PubKeyAlgo = %v, want %v", got, want)
		}
		// Verify flags.
		if subkey.Sig.FlagCertify || subkey.Sig.FlagSign {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Subkey signature authorized to sign")
		}
		if !subkey.Sig.FlagEncryptCommunications || !subkey.Sig.FlagEncryptStorage {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Subkey missing encrypt flag")
		}
		// Verify that hash is one of the preferred hash types.
		hashID, ok := s2k.HashToHashId(subkey.Sig.Hash)
		if !ok {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Invalid hash %v", subkey.Sig.Hash)
		}
		if _, ok := requiredHash[hashID]; !ok {
			return &Fingerprint{}, status.Errorf(status.InvalidArgument, "Hash algo %v not approved", hashID)
		}
	}
	// Only accept ECC keys.
	if got, want := entity.PrimaryKey.PubKeyAlgo, packet.PubKeyAlgoECDSA; got != want {
		return &Fingerprint{}, status.Errorf(status.InvalidArgument, "PubKeyAlgo = %v, want %v", got, want)
	}
	var fingerprint = Fingerprint(entity.PrimaryKey.Fingerprint)
	return &fingerprint, nil
}

// setEquals performs a set equality test between a and b.
func setEquals(aset map[uint8]bool, b []uint8) bool {
	// Catch duplicates in b
	bset := make(map[uint8]bool)
	for _, v := range b {
		bset[v] = true
	}
	return reflect.DeepEqual(aset, bset)
}
