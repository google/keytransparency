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

package keyserver

import (
	"errors"
	"io"
	"reflect"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
	"golang.org/x/crypto/openpgp/s2k"
)

var (
	// ErrEntityCount occurs when more than one entity is found.
	ErrEntityCount = errors.New("pgp: one entity allowed")
	// ErrRevocationCount occurs when a revocation is found.
	ErrRevocationCount = errors.New("pgp: no revocations allowed")
	// ErrSigCount occurs when more than one signature packet is found.
	ErrSigCount = errors.New("pgp: only self signature allowed")
	// ErrSubkeyCount occurs when more than one subkey is found.
	ErrSubkeyCount = errors.New("pgp: one subkey allowed")
	// ErrUserID occurs when the userid does not match the expected userid.
	ErrUserID = errors.New("pgp: wrong userID")
	// ErrMissingSelfSig occurs when the self signature packet is missing.
	ErrMissingSelfSig = errors.New("pgp: missing valid self signature")
	// ErrMissingSubkey occurs when a subkey is missing.
	ErrMissingSubkey = errors.New("pgp: missing valid subkey")
	// ErrExpiredSig occurs when a signature packet is expired.
	ErrExpiredSig = errors.New("pgp: expired signature")
	// ErrAlgo occurs when unsupported algorithms are used in a signature packet.
	ErrAlgo = errors.New("pgp: unsupported algorithm")
	// requiredSymmetric represents the required symmetric algorithm. 9 is
	// AES with 256-bit key.
	// More details here: https://tools.ietf.org/html/rfc4880#section-9.2.
	requiredSymmetric = map[uint8]bool{9: true}
	// requiredHash represents the required hash functions. 8 is SHA256, 9
	// is SHA384, 10 is SHA512, and 11 is SHA224.
	// More details here: https://tools.ietf.org/html/rfc4880#section-9.4.
	requiredHash = map[uint8]bool{8: true, 9: true, 10: true, 11: true}
)

// Fingerprint is the type used to identify keys.
type Fingerprint [20]byte

// validatePGP verifies that there is
// - One entity in the key ring.
// - One userID packet that matches the userID arg exactly.
// - One signature with the expected algorithm choices.
// - Signatures are within their valididty periods.
// - TODO: parameter checks for public key.
// returns fingerprint, error
//
func validatePGP(userID string, key io.Reader) (*Fingerprint, error) {
	// Verify signatures, check revocation.
	entityList, err := openpgp.ReadKeyRing(key)
	if err != nil {
		return nil, err
	}
	// Only allow one entity / identity key.
	if got, want := len(entityList), 1; got != want {
		return nil, ErrEntityCount
	}
	entity := entityList[0]

	// Only allow one identity / username.
	if got, want := len(entity.Identities), 1; got != want {
		return nil, ErrEntityCount
	}
	// No revocations allowed.
	if got, want := len(entity.Revocations), 0; want != got {
		return nil, ErrRevocationCount
	}
	// Verify the UserId.
	if err := verifyIdentities(entity.Identities, userID); err != nil {
		return nil, err
	}

	// Verify subkeys.
	if err := verifySubkeys(entity.Subkeys); err != nil {
		return nil, err
	}
	// Only accept ECC keys.
	if got, want := entity.PrimaryKey.PubKeyAlgo, packet.PubKeyAlgoECDSA; got != want {
		return nil, ErrAlgo
	}
	fingerprint := Fingerprint(entity.PrimaryKey.Fingerprint)
	return &fingerprint, nil
}

func verifyIdentities(identities map[string]*openpgp.Identity, userID string) error {
	for _, id := range identities {
		if got, want := id.UserId.Id, userID; got != want {
			return ErrUserID
		}
		if id.SelfSignature == nil {
			return ErrMissingSelfSig
		}
		if err := verifyIdentityMetadata(id); err != nil {
			return err
		}
		if err := verifyIdentityAlgo(id); err != nil {
			return err
		}
		// No extra signatures allowed.
		if got, want := len(id.Signatures), 0; want != got {
			return ErrSigCount
		}
	}
	return nil
}

func verifyIdentityMetadata(id *openpgp.Identity) error {
	// Verify timestamps.
	if id.SelfSignature.KeyExpired(time.Now()) {
		return ErrExpiredSig
	}
	// Verify flags.
	if !id.SelfSignature.FlagCertify || !id.SelfSignature.FlagSign {
		return ErrMissingSelfSig
	}
	if id.SelfSignature.FlagEncryptCommunications || id.SelfSignature.FlagEncryptStorage {
		return ErrMissingSelfSig
	}
	return nil
}

func verifyIdentityAlgo(id *openpgp.Identity) error {
	// Verify encryption types. AES-256
	if got, want := id.SelfSignature.PreferredSymmetric, requiredSymmetric; !setEquals(want, got) {
		return ErrAlgo
	}
	// Verify preferred hash types.
	if got, want := id.SelfSignature.PreferredHash, requiredHash; !setEquals(want, got) {
		return ErrAlgo
	}
	// Verify that hash is one of the preferred hash types.
	hashID, ok := s2k.HashToHashId(id.SelfSignature.Hash)
	if !ok {
		return ErrAlgo
	}
	if _, ok := requiredHash[hashID]; !ok {
		return ErrAlgo
	}
	return nil
}

func verifySubkeys(subkeys []openpgp.Subkey) error {
	// Only allow one subkey.
	if got, want := len(subkeys), 1; want != got {
		return ErrSubkeyCount
	}
	for _, subkey := range subkeys {
		if err := verifySubkeyMetadata(subkey); err != nil {
			return err
		}
		if err := verifySubkeyAlgo(subkey); err != nil {
			return err
		}
	}
	return nil
}

func verifySubkeyMetadata(subkey openpgp.Subkey) error {
	// Verify expiration.
	if subkey.Sig.KeyExpired(time.Now()) {
		return ErrExpiredSig
	}
	// Verify flags.
	if subkey.Sig.FlagCertify || subkey.Sig.FlagSign {
		return ErrMissingSubkey
	}
	if !subkey.Sig.FlagEncryptCommunications || !subkey.Sig.FlagEncryptStorage {
		return ErrMissingSubkey
	}
	return nil
}

func verifySubkeyAlgo(subkey openpgp.Subkey) error {
	// Only accept ECC keys.
	if got, want := subkey.PublicKey.PubKeyAlgo, packet.PubKeyAlgoECDH; got != want {
		return ErrAlgo
	}
	// Verify that hash is one of the preferred hash types.
	hashID, ok := s2k.HashToHashId(subkey.Sig.Hash)
	if !ok {
		return ErrAlgo
	}
	if _, ok := requiredHash[hashID]; !ok {
		return ErrAlgo
	}
	return nil
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
