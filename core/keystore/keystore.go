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

package keystore

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/keytransparency/core/signatures"
	"github.com/google/keytransparency/core/signatures/factory"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"

	kmpb "github.com/google/keytransparency/core/proto/keymaster"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

var (
	// ErrKeyNotExist occurs when the key being removed does not exist.
	ErrKeyNotExist = errors.New("key does not exist")
)

// KeyStore contains all update signing and verification keys.
type KeyStore struct {
	signers      map[string]signatures.Signer
	verifiers    map[string]signatures.Verifier
	activeSigner signatures.Signer
}

// New creates a new instance of an empty key store.
func New() *KeyStore {
	return &KeyStore{
		signers:   make(map[string]signatures.Signer),
		verifiers: make(map[string]signatures.Verifier),
	}
}

// Unmarshal unmarshals the provided protobuf into a key store object.
func Unmarshal(buf []byte, store *KeyStore) error {
	set := new(kmpb.KeySet)
	if err := proto.Unmarshal(buf, set); err != nil {
		return err
	}

	// Populate signers map.
	var activeSigner signatures.Signer
	signers := make(map[string]signatures.Signer)
	for id, key := range set.SigningKeys {
		addedAt, err := ptypes.Timestamp(key.Metadata.AddedAt)
		if err != nil {
			return err
		}
		signer, err := factory.NewSigner(key.KeyMaterial, addedAt, key.Metadata.Description, key.Status)
		if err != nil {
			return err
		}
		signers[id] = signer
		if key.Status == kmpb.SigningKey_ACTIVE {
			activeSigner = signer
		}
	}

	// Populate verifiers map.
	verifiers := make(map[string]signatures.Verifier)
	for id, key := range set.VerifyingKeys {
		addedAt, err := ptypes.Timestamp(key.Metadata.AddedAt)
		if err != nil {
			return err
		}
		verifier, err := factory.NewVerifier(key.KeyMaterial, addedAt, key.Metadata.Description, key.Status)
		if err != nil {
			return err
		}
		verifiers[id] = verifier
	}

	if store == nil {
		store = New()
	}
	store.signers = signers
	store.verifiers = verifiers
	store.activeSigner = activeSigner
	return nil
}

// Marshal marshals a key store object into a protobuf-formatted byte slice.
func (s *KeyStore) Marshal() ([]byte, error) {
	signingKeys := make(map[string]*kmpb.SigningKey)
	for id, signer := range s.signers {
		key, err := signer.Marshal()
		if err != nil {
			return nil, err
		}
		signingKeys[id] = key
	}

	verifyingKeys := make(map[string]*kmpb.VerifyingKey)
	for id, verifier := range s.verifiers {
		key, err := verifier.Marshal()
		if err != nil {
			return nil, err
		}
		verifyingKeys[id] = key
	}

	buf, err := proto.Marshal(&kmpb.KeySet{
		SigningKeys:   signingKeys,
		VerifyingKeys: verifyingKeys,
	})
	if err != nil {
		return nil, err
	}
	return buf, nil
}

// AddSigningKey adds a new private key to the store.
func (s *KeyStore) AddSigningKey(status kmpb.SigningKey_KeyStatus, description string, key []byte) (string, error) {
	signer, err := factory.NewSigner(key, time.Now(), description, status)
	if err != nil {
		return "", nil
	}

	mapID := signer.KeyID()
	if _, ok := s.signers[mapID]; ok {
		return "", fmt.Errorf("key with ID %v already exists", mapID)
	}
	s.signers[mapID] = signer

	// Activate the added signing key.
	if status == kmpb.SigningKey_ACTIVE {
		if err := s.Activate(mapID); err != nil {
			return "", err
		}
	}
	return mapID, nil
}

// AddVerifyingKey adds a new public key to the store.
func (s *KeyStore) AddVerifyingKey(description string, key []byte) (string, error) {
	verifier, err := factory.NewVerifier(key, time.Now(), description, kmpb.VerifyingKey_ACTIVE)
	if err != nil {
		return "", err
	}

	mapID := verifier.KeyID()
	if _, ok := s.verifiers[mapID]; ok {
		return "", fmt.Errorf("key with ID %v already exists", mapID)
	}
	s.verifiers[mapID] = verifier

	return mapID, nil
}

// RemoveSigningKey marks a private key as deprecated. Keys are not permanently
// removed. Active keys cannot be removed.
func (s *KeyStore) RemoveSigningKey(keyID string) error {
	if _, ok := s.signers[keyID]; !ok {
		return ErrKeyNotExist
	}
	if s.signers[keyID].Status() == kmpb.SigningKey_ACTIVE {
		return errors.New("cannot remove an active key")
	}

	s.signers[keyID].Deprecate()
	return nil
}

// RemoveVerifyingKey marks a public key as deprecated. Keys are not permanently
// removed. If the key being removed is the only non-deprecated one, it cannot
// be deleted. This prevents account lockout.
func (s *KeyStore) RemoveVerifyingKey(keyID string) error {
	if _, ok := s.verifiers[keyID]; !ok {
		return ErrKeyNotExist
	}

	// Make sure the key being removed is not the only active one.
	exist := false
	for id, verifier := range s.verifiers {
		if id == keyID {
			continue
		}
		if verifier.Status() == kmpb.VerifyingKey_ACTIVE {
			exist = true
			break
		}
	}
	if !exist {
		return fmt.Errorf("cannot remove the only verifying key %v", keyID)
	}

	s.verifiers[keyID].Deprecate()
	return nil
}

// Activate activates a list of private keys given their IDs. All other private
// keys are marked as inactive. Deprecated keys cannot be activated.
func (s *KeyStore) Activate(keyID string) error {
	signer, ok := s.signers[keyID]
	if !ok {
		return ErrKeyNotExist
	}

	if signer.Status() == kmpb.SigningKey_DEPRECATED {
		return fmt.Errorf("cannot activate deprecated key %v", keyID)
	}

	// Deactivate already active keys and active the new one.
	if s.activeSigner != nil {
		s.activeSigner.Deactivate()
	}
	s.signers[keyID].Activate()
	s.activeSigner = s.signers[keyID]
	return nil
}

type bySigningKeyAddedAt []*kmpb.SigningKey

func (s bySigningKeyAddedAt) Len() int      { return len(s) }
func (s bySigningKeyAddedAt) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s bySigningKeyAddedAt) Less(i, j int) bool {
	iTime, err := ptypes.Timestamp(s[i].Metadata.AddedAt)
	if err != nil {
		panic(err)
	}
	jTime, err := ptypes.Timestamp(s[j].Metadata.AddedAt)
	if err != nil {
		panic(err)
	}
	return jTime.Before(iTime)
}

type byVerifyingKeyAddedAt []*kmpb.VerifyingKey

func (s byVerifyingKeyAddedAt) Len() int      { return len(s) }
func (s byVerifyingKeyAddedAt) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byVerifyingKeyAddedAt) Less(i, j int) bool {
	iTime, err := ptypes.Timestamp(s[i].Metadata.AddedAt)
	if err != nil {
		panic(err)
	}
	jTime, err := ptypes.Timestamp(s[j].Metadata.AddedAt)
	if err != nil {
		panic(err)
	}
	return jTime.Before(iTime)
}

// Info returns two list of private and public keys info. The actual key material
// is not include in the results.
func (s *KeyStore) Info() ([]*kmpb.SigningKey, []*kmpb.VerifyingKey, error) {
	// Getting signing keys info.
	signingInfo := make([]*kmpb.SigningKey, 0, len(s.signers))
	for _, signer := range s.signers {
		key, err := signer.Marshal()
		if err != nil {
			return nil, nil, err
		}
		key.KeyMaterial = nil
		signingInfo = append(signingInfo, key)
	}

	// Getting verifying keys info
	verifyingInfo := make([]*kmpb.VerifyingKey, 0, len(s.verifiers))
	for _, verifier := range s.verifiers {
		key, err := verifier.Marshal()
		if err != nil {
			return nil, nil, err
		}
		key.KeyMaterial = nil
		verifyingInfo = append(verifyingInfo, key)
	}

	// Sort and return the result.
	sort.Sort(bySigningKeyAddedAt(signingInfo))
	sort.Sort(byVerifyingKeyAddedAt(verifyingInfo))
	return signingInfo, verifyingInfo, nil
}

// Signer returns a signer object given the corresponding key ID.
func (s *KeyStore) Signer(keyID string) (signatures.Signer, error) {
	signer, ok := s.signers[keyID]
	if !ok {
		return nil, ErrKeyNotExist
	}
	return signer, nil
}

// Signers returns a list of signers created using all active private keys.
func (s *KeyStore) Signers() []signatures.Signer {
	signers := make([]signatures.Signer, 0, len(s.signers))
	for _, signer := range s.signers {
		if signer.Status() == kmpb.SigningKey_ACTIVE {
			signers = append(signers, signer.Clone())
		}
	}
	return signers
}

// PublicKeys returns a list of public keys created using all active public keys.
func (s *KeyStore) PublicKeys() ([]*tpb.PublicKey, error) {
	publicKeys := make([]*tpb.PublicKey, 0, len(s.verifiers))
	for _, verifier := range s.verifiers {
		if verifier.Status() == kmpb.VerifyingKey_ACTIVE {
			publicKey, err := verifier.PublicKey()
			if err != nil {
				return nil, err
			}
			publicKeys = append(publicKeys, publicKey)
		}
	}
	return publicKeys, nil
}

// KeyIDs returns a list of all signing and verifying key IDs.
func (s *KeyStore) KeyIDs() []string {
	// Some singing and verifying keys might have the same key ID. Since Go
	// does not have a set type, a map is used to filter out duplicates.
	idsMap := make(map[string]bool)
	for _, signer := range s.signers {
		idsMap[signer.KeyID()] = true
	}
	for _, verifier := range s.verifiers {
		idsMap[verifier.KeyID()] = true
	}

	ids := make([]string, 0, len(idsMap))
	for id := range idsMap {
		ids = append(ids, id)
	}
	return ids
}
