// Copyright 2017 Google Inc. All Rights Reserved.
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
	"testing"

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/mutator"

	"github.com/benlaurie/objecthash/go/objecthash"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

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
	emptyEntryData, err := createEntry([]byte{}, []string{testPubKey1})
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
	// nilHash is used as the previous hash value when submitting the very
	// first mutation.
	nilHash := objecthash.ObjectHash(nil)
	// Set hash for first entries correctly, then hash it for the next entry:
	entryData1.Previous = nilHash[:]
	hashEntry1 := objecthash.ObjectHash(entryData1)
	missingKeyEntryData1.Previous = nilHash[:]
	hashMissingKeyEntry1 := objecthash.ObjectHash(missingKeyEntryData1)

	// Create signers.
	signers1 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)})
	signers2 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey2)})
	signers3 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1), []byte(testPrivKey2)})

	for i, tc := range []struct {
		key      []byte
		oldEntry *tpb.Entry
		newEntry *tpb.Entry
		previous []byte
		signers  []signatures.Signer
		err      error
	}{
		{key, entryData2, entryData2, hashEntry1[:], nil, mutator.ErrReplay},    // Replayed mutation
		{largeKey, entryData1, entryData2, hashEntry1[:], nil, mutator.ErrSize}, // Large mutation
		{key, entryData1, entryData2, nil, nil, mutator.ErrPreviousHash},        // Invalid previous entry hash
		{key, nil, entryData1, nil, nil, mutator.ErrPreviousHash},               // Very first mutation, invalid previous entry hash
		{key, nil, &tpb.Entry{}, nil, nil, mutator.ErrPreviousHash},             // Very first mutation, invalid previous entry hash
		{key, nil, emptyEntryData, nilHash[:], signers1, nil},                   // Very first mutation, empty commitment, working case
		{key, nil, entryData1, nilHash[:], signers1, nil},                       // Very first mutation, working case
		{key, entryData1, entryData2, hashEntry1[:], signers3, nil},             // Second mutation, working case
		// Test missing keys and signature cases.
		{key, nil, missingKeyEntryData1, nilHash[:], signers1, mutator.ErrMissingKey},                       // Very first mutation, missing current key
		{key, nil, entryData1, nilHash[:], []signatures.Signer{}, mutator.ErrUnauthorized},                  // Very first mutation, missing current signature
		{key, missingKeyEntryData1, entryData2, hashMissingKeyEntry1[:], signers3, mutator.ErrUnauthorized}, // Second mutation, Missing previous authorized key
		{key, entryData1, entryData2, hashEntry1[:], signers2, mutator.ErrUnauthorized},                     // Second mutation, missing previous signature
		{key, entryData1, missingKeyEntryData2, hashEntry1[:], signers3, nil},                               // Second mutation, missing current authorized key
		{key, entryData1, entryData2, hashEntry1[:], signers1, nil},                                         // Second mutation, missing current signature, should work
	} {
		// Prepare mutations.
		mutation, err := prepareMutation(tc.key, tc.newEntry, tc.previous, tc.signers)
		if err != nil {
			t.Fatalf("prepareMutation(%v, %v, %v)=%v", tc.key, tc.newEntry, tc.previous, err)
		}

		if _, got := New().Mutate(tc.oldEntry, mutation); got != tc.err {
			t.Errorf("%d Mutate(%v, %v)=%v, want %v", i, tc.oldEntry, mutation, got, tc.err)
		}
	}
}
