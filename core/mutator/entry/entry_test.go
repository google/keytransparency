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
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/google/key-transparency/core/mutator"
	"github.com/google/key-transparency/core/signatures"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/proto"

	"github.com/google/key-transparency/core/proto/ctmap"
	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
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

func createEntry(commitment []byte, pkeys []string) ([]byte, error) {
	authKeys := make([]*tpb.PublicKey, len(pkeys))
	for i, key := range pkeys {
		p, _ := pem.Decode([]byte(key))
		if p == nil {
			return nil, fmt.Errorf("no PEM block found")
		}
		authKeys[i] = &tpb.PublicKey{
			KeyType: &tpb.PublicKey_EcdsaVerifyingP256{
				EcdsaVerifyingP256: p.Bytes,
			},
		}
	}

	entry := &tpb.Entry{
		Commitment:     commitment,
		AuthorizedKeys: authKeys,
	}
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", entry, err)
	}
	return entryData, nil
}

func prepareMutation(key []byte, entryData []byte, previous []byte, signers []signatures.Signer) ([]byte, error) {
	kv := &tpb.KeyValue{
		Key:   key,
		Value: entryData,
	}

	// Populate signatures map.
	sigs := make(map[string]*ctmap.DigitallySigned)
	for _, signer := range signers {
		sig, err := signer.Sign(*kv)
		if err != nil {
			return nil, fmt.Errorf("signerSign() failed: %v", err)
		}
		sigs[signer.KeyID()] = sig
	}

	skv := &tpb.SignedKV{
		KeyValue:   kv,
		Signatures: sigs,
		Previous:   previous,
	}
	mutation, err := proto.Marshal(skv)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", skv, err)
	}
	return mutation, nil
}

func signersFromPEMs(t *testing.T, keys [][]byte) []signatures.Signer {
	signers := make([]signatures.Signer, 0, len(keys))
	for _, key := range keys {
		signer, err := signatures.SignerFromPEM(rand.Reader, key)
		if err != nil {
			t.Fatalf("NewSigner(): %v", err)
		}
		signers = append(signers, signer)
	}
	return signers
}

func TestCheckMutation(t *testing.T) {
	// The passed commitment to createEntry is a dummy value. It is needed to
	// make the two entries (entryData1 and entryData2) different, otherwise
	// it is not possible to test all cases.
	entryData1, err := createEntry([]byte{1}, []string{testPubKey1})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	missingKeyEntryData1, err := createEntry([]byte{1}, []string{})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	entryData2, err := createEntry([]byte{2}, []string{testPubKey2})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	missingKeyEntryData2, err := createEntry([]byte{2}, []string{testPubKey1})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	key := []byte{0}
	largeKey := bytes.Repeat(key, mutator.MaxMutationSize)

	// Calculate hashes.
	hashEntry1 := objecthash.ObjectHash(entryData1)
	hashMissingKeyEntry1 := objecthash.ObjectHash(missingKeyEntryData1)
	// nilHash is used as the previous hash value when submitting the very
	// first mutation.
	nilHash := objecthash.ObjectHash(nil)

	// Create signers.
	signers1 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)})
	signers2 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey2)})
	signers3 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1), []byte(testPrivKey2)})

	for _, tc := range []struct {
		key       []byte
		oldValue  []byte
		entryData []byte
		previous  []byte
		signers   []signatures.Signer
		err       error
	}{
		{key, entryData2, entryData2, hashEntry1[:], nil, mutator.ErrReplay},    // Replayed mutation
		{largeKey, entryData1, entryData2, hashEntry1[:], nil, mutator.ErrSize}, // Large mutation
		{key, entryData1, entryData2, nil, nil, mutator.ErrPreviousHash},        // Invalid previous entry hash
		{key, nil, entryData1, nil, nil, mutator.ErrPreviousHash},               // Very first mutation, invalid previous entry hash
		{key, nil, nil, nil, nil, mutator.ErrReplay},                            // Very first mutation, replayed mutation
		{key, nil, entryData1, nilHash[:], signers1, nil},                       // Very first mutation, working case
		{key, entryData1, entryData2, hashEntry1[:], signers3, nil},             // Second mutation, working case
		// Test missing keys and signature cases.
		{key, nil, missingKeyEntryData1, nilHash[:], signers1, mutator.ErrMissingKey},                     // Very first mutation, missing current key
		{key, nil, entryData1, nilHash[:], []signatures.Signer{}, mutator.ErrInvalidSig},                  // Very first mutation, missing current signature
		{key, missingKeyEntryData1, entryData2, hashMissingKeyEntry1[:], signers3, mutator.ErrInvalidSig}, // Second mutation, Missing previous authorized key
		{key, entryData1, entryData2, hashEntry1[:], signers2, mutator.ErrInvalidSig},                     // Second mutation, missing previous signature
		{key, entryData1, missingKeyEntryData2, hashEntry1[:], signers3, nil},                             // Second mutation, missing current authorized key
		{key, entryData1, entryData2, hashEntry1[:], signers1, mutator.ErrInvalidSig},                     // Second mutation, missing current signature
	} {
		// Prepare mutations.
		mutation, err := prepareMutation(tc.key, tc.entryData, tc.previous, tc.signers)
		if err != nil {
			t.Fatalf("prepareMutation(%v, %v, %v)=%v", tc.key, tc.entryData, tc.previous, err)
		}

		if got := New().CheckMutation(tc.oldValue, mutation); got != tc.err {
			t.Errorf("CheckMutation(%v, %v)=%v, want %v", tc.oldValue, mutation, got, tc.err)
		}
	}
}
