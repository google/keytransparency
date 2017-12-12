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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sort"
	"testing"

	"github.com/google/keytransparency/core/crypto/signatures"

	kmpb "github.com/google/keytransparency/core/api/type/type_proto"
)

type testKey struct {
	// privKey and pubKey contains PEM-formatted keys.
	privKey []byte
	pubKey  []byte
	// keyID contains the hash of the public key in hex format.
	keyID string
}

var (
	signingStatuses = []kmpb.SigningKey_KeyStatus{
		kmpb.SigningKey_INACTIVE,
		kmpb.SigningKey_DEPRECATED,
		kmpb.SigningKey_ACTIVE,
		kmpb.SigningKey_INACTIVE,
	}
	verifyingStatuses = []kmpb.VerifyingKey_KeyStatus{
		kmpb.VerifyingKey_ACTIVE,
		kmpb.VerifyingKey_DEPRECATED,
		kmpb.VerifyingKey_ACTIVE,
	}
)

func generateTestKeys(count int) ([]*testKey, error) {
	keys := make([]*testKey, 0, count)
	for i := 0; i < count; i++ {
		key, err := generateTestKey()
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

func generateTestKey() (*testKey, error) {
	p256Curve := elliptic.P256()

	// Private key.
	sk, err := ecdsa.GenerateKey(p256Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ecdsa.GenerateKey() failed: %v", err)
	}
	skBytes, err := x509.MarshalECPrivateKey(sk)
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalECPrivateKey() failed: %v", err)
	}
	skPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: skBytes,
		},
	)

	// Public key.
	pkBytes, err := x509.MarshalPKIXPublicKey(sk.Public())
	if err != nil {
		return nil, fmt.Errorf("x509.MarshalPKIXPublicKey() failed: %v", err)
	}
	pkPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	keyID, err := signatures.KeyID(sk.Public())
	if err != nil {
		return nil, fmt.Errorf("signatures.KeyID() failes: %v", err)
	}

	return &testKey{
		privKey: skPEM,
		pubKey:  pkPEM,
		keyID:   keyID,
	}, nil
}

func addKeys(store *KeyMaster, keys []*testKey) error {
	// Add signing keys.
	for i, status := range signingStatuses {
		description := fmt.Sprintf("description_%v", i)
		if _, err := store.AddSigningKey(status, description, keys[i].privKey); err != nil {
			return err
		}
	}

	// Add verifying keys.
	for i, status := range verifyingStatuses {
		description := fmt.Sprintf("description_%v", i)
		keyID, err := store.AddVerifyingKey(description, keys[i].pubKey)
		if err != nil {
			return err
		}
		if status == kmpb.VerifyingKey_DEPRECATED {
			if err := store.RemoveVerifyingKey(keyID); err != nil {
				return nil
			}
		}
	}

	return nil
}

func TestAdd(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}
	checkAddedSigningKeys(t, store, keys)
	checkAddedVerifyingKeys(t, store, keys)
}

func checkAddedSigningKeys(t *testing.T, store *KeyMaster, keys []*testKey) {
	for i := 0; i < len(store.signers); i++ {
		testKey := keys[i]
		description := fmt.Sprintf("description_%v", i)
		signer, ok := store.signers[testKey.keyID]
		if got, want := ok, true; got != want {
			t.Errorf("store.signers[%v]=%v, want %v", testKey.keyID, got, want)
			continue
		}
		key, err := signer.Marshal()
		if err != nil {
			t.Errorf("store.signers[%v].Marshal() failed: %v", i, err)
			continue
		}

		// Check metadata.
		if got, want := key.Metadata.KeyId, testKey.keyID; got != want {
			t.Errorf("signingKeys[%v].Metadata.KeyId=%v, want %v", testKey.keyID, got, want)
		}
		if got, want := key.Status, signingStatuses[i]; got != want {
			t.Errorf("signingKeys[%v].Status=%v, want %v", testKey.keyID, got, want)
		}
		if got, want := key.Metadata.Description, description; got != want {
			t.Errorf("signingKeys[%v].Metadata.Description=%v, want %v", testKey.keyID, got, want)
		}

		// Check key material.
		gotBlock, _ := pem.Decode(key.KeyMaterial)
		wantBlock, _ := pem.Decode(testKey.privKey)
		if got, want := gotBlock.Bytes, wantBlock.Bytes; !bytes.Equal(got, want) {
			t.Errorf("signingKeys[%v].KeyMaterial=%v, want %v", testKey.keyID, got, want)
		}
	}
}

func checkAddedVerifyingKeys(t *testing.T, store *KeyMaster, keys []*testKey) {
	for i := 0; i < len(store.verifiers); i++ {
		testKey := keys[i]
		description := fmt.Sprintf("description_%v", i)
		verifier, ok := store.verifiers[testKey.keyID]
		if got, want := ok, true; got != want {
			t.Errorf("store.keySet.VerifyingKeys[%v]=%v, want %v", testKey.keyID, got, want)
			continue
		}
		key, err := verifier.Marshal()
		if err != nil {
			t.Errorf("store.verifiers[%v].Marshal() failed: %v", i, err)
			continue
		}

		// Check metadata.
		if got, want := key.Metadata.KeyId, testKey.keyID; got != want {
			t.Errorf("verifyingKeys[%v].Metadata.KeyId=%v, want %v", testKey.keyID, got, want)
		}
		if got, want := key.Status, verifyingStatuses[i]; got != want {
			t.Errorf("verifyingKeys[%v].Status=%v, want %v", testKey.keyID, got, want)
		}
		if got, want := key.Metadata.Description, description; got != want {
			t.Errorf("verifyingKeys[%v].Metadata.Description=%v, want %v", testKey.keyID, got, want)
		}

		// Check key material.
		gotBlock, _ := pem.Decode(key.KeyMaterial)
		wantBlock, _ := pem.Decode(testKey.pubKey)
		if got, want := gotBlock.Bytes, wantBlock.Bytes; !bytes.Equal(got, want) {
			t.Errorf("verifyingKeys[%v].KeyMaterial=%v, want %v", testKey.keyID, got, want)
		}
	}
}

func TestAddDuplicateSigningKey(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(1)
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if _, err := store.AddSigningKey(kmpb.SigningKey_ACTIVE, "duplicate_description_1", keys[0].privKey); err != nil {
		t.Fatalf("store.AddSigningKey() failed: %v", err)
	}
	if _, err := store.AddSigningKey(kmpb.SigningKey_ACTIVE, "duplicate_description_2", keys[0].privKey); err == nil {
		t.Error("adding signing keys with duplicate IDs unexpectedly succeeded")
	}
}

func TestAddDuplicateVerifyingKey(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(1)
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if _, err := store.AddVerifyingKey("duplicate_description_1", keys[0].pubKey); err != nil {
		t.Fatalf("store.AddVerifyingKey() failed: %v", err)
	}
	if _, err := store.AddVerifyingKey("duplicate_description_2", keys[0].pubKey); err == nil {
		t.Error("adding verifying keys with duplicate IDs unexpectedly succeeded")
	}
}

func TestRemoveSigningKey(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	for _, tc := range []struct {
		keyID   string
		success bool
	}{
		{keys[0].keyID, true},                 // working case
		{keys[2].keyID, false},                // active key
		{"some_random_signing_key_id", false}, // key does not exist
	} {
		err := store.RemoveSigningKey(tc.keyID)
		if got, want := err == nil, tc.success; got != want {
			t.Fatalf("store.RemoveSigingKey(%v)=%v, want nil error=%v", tc.keyID, err, want)
		}
		if err != nil {
			continue
		}

		if got, want := store.signers[tc.keyID].Status(), kmpb.SigningKey_DEPRECATED; got != want {
			t.Errorf("store.signers[%v].Status()=%v, want %v", tc.keyID, got, want)
		}
	}
}

func TestRemoveVerifyingKey(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	for _, tc := range []struct {
		keyID   string
		success bool
	}{
		{keys[0].keyID, true},                   // working case
		{keys[2].keyID, false},                  // active key
		{"some_random_verifying_key_id", false}, // key does not exist
	} {
		err := store.RemoveVerifyingKey(tc.keyID)
		if got, want := err == nil, tc.success; got != want {
			t.Fatalf("store.RemoveSigingKey(%v)=%v, want nil error=%v", tc.keyID, err, want)
		}
		if err != nil {
			continue
		}

		if got, want := store.verifiers[tc.keyID].Status(), kmpb.VerifyingKey_DEPRECATED; got != want {
			t.Errorf("store.verifiers[%v].Status()=%v, want %v", tc.keyID, got, want)
		}
	}
}

func TestActivate(t *testing.T) {
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}

	for _, tc := range []struct {
		id      string
		success bool
	}{
		{keys[0].keyID, true},
		{keys[1].keyID, false},
	} {
		store := New()
		if err := addKeys(store, keys); err != nil {
			t.Fatalf("addKeys() failed: %v", err)
		}

		err = store.Activate(tc.id)
		if got, want := err == nil, tc.success; got != want {
			t.Fatalf("store.Activate(%v)=%v, want nil error=%v", tc.id, err, want)
		}
		if err != nil {
			continue
		}

		// Check that only the activated key is active.
		if got, want := store.signers[tc.id].Status(), kmpb.SigningKey_ACTIVE; got != want {
			t.Errorf("store.signers[%v].Status()=%v, want %v", tc.id, got, want)
		}
		for id, signer := range store.signers {
			if id == tc.id {
				continue
			}
			if got, want := signer.Status(), kmpb.SigningKey_ACTIVE; got == want {
				t.Errorf("store.signers[%v].Status=%v, does not want %v", id, got, want)
			}
		}
	}
}

type bySigningKeyDescription []*kmpb.SigningKey

func (s bySigningKeyDescription) Len() int      { return len(s) }
func (s bySigningKeyDescription) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s bySigningKeyDescription) Less(i, j int) bool {
	return s[i].Metadata.Description < s[j].Metadata.Description
}

type byVerifyingKeyDescription []*kmpb.VerifyingKey

func (s byVerifyingKeyDescription) Len() int      { return len(s) }
func (s byVerifyingKeyDescription) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
func (s byVerifyingKeyDescription) Less(i, j int) bool {
	return s[i].Metadata.Description < s[j].Metadata.Description
}

func TestInfo(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	signingInfo, verifyingInfo, err := store.Info()
	if err != nil {
		t.Fatalf("store.Info() failed: %v", err)
	}
	checkSigningKeysInfo(t, signingInfo, store, keys)
	checkVerifyingKeysInfo(t, verifyingInfo, store, keys)
}

func checkSigningKeysInfo(t *testing.T, signingInfo []*kmpb.SigningKey, store *KeyMaster, keys []*testKey) {
	// Check correctness of signing keys info.
	sort.Sort(bySigningKeyDescription(signingInfo))
	for i, info := range signingInfo {
		key, err := store.signers[keys[i].keyID].Marshal()
		if err != nil {
			t.Errorf("store.signers[%v].Marshal() failed: %v", keys[i].keyID, err)
		}

		if got, want := info.Metadata.KeyId, keys[i].keyID; got != want {
			t.Errorf("info.Metadata.KeyId=%v, want %v", got, want)
		}
		if got, want := info.Status, key.Status; got != want {
			t.Errorf("info.Status=%v, want %v", got, want)
		}
		if got, want := info.Metadata.Description, key.Metadata.Description; got != want {
			t.Errorf("info.Metadata.Description=%v, want %v", got, want)
		}
	}
}

func checkVerifyingKeysInfo(t *testing.T, verifyingInfo []*kmpb.VerifyingKey, store *KeyMaster, keys []*testKey) {
	// Check correctness of verifying keys info.
	sort.Sort(byVerifyingKeyDescription(verifyingInfo))
	for i, info := range verifyingInfo {
		key, err := store.verifiers[keys[i].keyID].Marshal()
		if err != nil {
			t.Errorf("store.verifiers[%v].Marshal() failed: %v", keys[i].keyID, err)
		}

		if got, want := info.Metadata.KeyId, keys[i].keyID; got != want {
			t.Errorf("info.Metadata.KeyId=%v, want %v", got, want)
		}
		if got, want := info.Status, key.Status; got != want {
			t.Errorf("info.Status=%v, want %v", got, want)
		}
		if got, want := info.Metadata.Description, key.Metadata.Description; got != want {
			t.Errorf("info.Metadata.Description=%v, want %v", got, want)
		}
	}
}

func TestSigner(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	for _, tc := range []struct {
		id      string
		success bool
	}{
		{keys[0].keyID, true},
		{"some_random_key_id", false},
	} {
		_, err := store.Signer(tc.id)
		if got, want := err == nil, tc.success; got != want {
			t.Errorf("store.Signer(%v)=%v, want nil error=%v", tc.id, got, want)
		}
	}
}

func TestSigners(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	signers := store.Signers()
	if got, want := len(signers), 1; got != want {
		t.Errorf("len(store.Signers())=%v, want %v", got, want)
	}
}

func TestPublicKeys(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	pKeys, err := store.PublicKeys()
	if err != nil {
		t.Fatalf("store.PublicKeys() failed: %v", err)
	}
	if got, want := len(pKeys), 2; got != want {
		t.Errorf("len(store.PublicKeys())=%v, want %v", got, want)
	}
}

func TestMarshalling(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}
	buf, err := store.Marshal()
	if err != nil {
		t.Fatalf("store.Marshal() failed: %v", err)
	}
	unmarshalledStore := New()
	if err := Unmarshal(buf, unmarshalledStore); err != nil {
		t.Fatalf("Unmarshal() failed: %v", err)
	}
	checkAddedSigningKeys(t, unmarshalledStore, keys)
	checkAddedVerifyingKeys(t, unmarshalledStore, keys)
}

func TestKeyIDs(t *testing.T) {
	store := New()
	keys, err := generateTestKeys(len(signingStatuses))
	if err != nil {
		t.Fatalf("generateTestKeys(%v) failed: %v", len(signingStatuses), err)
	}
	if err := addKeys(store, keys); err != nil {
		t.Fatalf("addKeys() failed: %v", err)
	}

	idsMap := make(map[string]bool)
	for _, key := range keys {
		idsMap[key.keyID] = true
	}

	keyIDs := store.KeyIDs()
	if got, want := len(keyIDs), len(idsMap); got != want {
		t.Errorf("len(store.KeyIDs())=%v, want %v", got, want)
	}
	for _, id := range keyIDs {
		if _, ok := idsMap[id]; !ok {
			t.Errorf("idsMap[%v]=false, want true", id)
		}
	}
}
