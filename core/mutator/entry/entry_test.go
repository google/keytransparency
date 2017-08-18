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
	"encoding/pem"
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/crypto/dev"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/protobuf/proto"

	"crypto/sha256"
	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian/crypto/sigpb"
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

func createEntry(commitment []byte, pkeys []string) (*tpb.Entry, error) {
	authKeys := make([]*tpb.PublicKey, len(pkeys))
	for i, key := range pkeys {
		p, _ := pem.Decode([]byte(key))
		if p == nil {
			return nil, errors.New("no PEM block found")
		}
		authKeys[i] = &tpb.PublicKey{
			KeyType: &tpb.PublicKey_EcdsaVerifyingP256{
				EcdsaVerifyingP256: p.Bytes,
			},
		}
	}

	return &tpb.Entry{
		Commitment:     commitment,
		AuthorizedKeys: authKeys,
	}, nil
}

func prepareSignedKV(key []byte, entry *tpb.Entry, previous []byte, signers []signatures.Signer) (*tpb.SignedKV, error) {
	if entry == nil {
		return nil, nil
	}
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", entry, err)
	}
	kv := &tpb.KeyValue{
		Key:   key,
		Value: entryData,
	}

	// Populate signatures map.
	sigs := make(map[string]*sigpb.DigitallySigned)
	for _, signer := range signers {
		sig, err := signer.Sign(*kv)
		if err != nil {
			return nil, fmt.Errorf("signerSign() failed: %v", err)
		}
		sigs[signer.KeyID()] = sig
	}

	return &tpb.SignedKV{
		KeyValue:   kv,
		Signatures: sigs,
		Previous:   previous,
	}, nil
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

	// Create signers.
	signers1 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)})
	signers2 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey2)})
	signers3 := signersFromPEMs(t, [][]byte{[]byte(testPrivKey1), []byte(testPrivKey2)})

	// Calculate hashes:
	//
	// nilHash is used as the previous hash value when submitting the very
	// first mutation.
	nilHash := sha256.Sum256(nil)
	update1, _ := prepareSignedKV(key, entryData1, nilHash[:], signers1)
	leaf1, _ := proto.Marshal(update1)
	hashEntry1 := sha256.Sum256(leaf1)
	missingKeyEntryData1Update, _ := prepareSignedKV(key, missingKeyEntryData1, nilHash[:], signers1)
	leaf2, _ := proto.Marshal(missingKeyEntryData1Update)
	hashMissingKeyEntry1 := sha256.Sum256(leaf2)

	for i, tc := range []struct {
		key        []byte
		oldEntry   *tpb.Entry
		newEntry   *tpb.Entry
		oldPrev    []byte
		newPrev    []byte
		oldSigners []signatures.Signer
		newSigners []signatures.Signer
		err        error
	}{
		{key, entryData2, entryData2, hashEntry1[:], hashEntry1[:], signers2, signers2, mutator.ErrReplay}, // Replayed mutation
		{largeKey, entryData1, entryData2, nil, hashEntry1[:], nil, signers2, mutator.ErrSize},             // Large mutation
		{key, entryData1, entryData2, nil, nil, nil, nil, mutator.ErrPreviousHash},                         // Invalid previous entry hash
		{key, nil, entryData1, nil, nil, nil, nil, mutator.ErrPreviousHash},                                // Very first mutation, invalid previous entry hash
		{key, nil, &tpb.Entry{}, nil, nil, nil, nil, mutator.ErrPreviousHash},                              // Very first mutation, invalid previous entry hash
		{key, nil, emptyEntryData, nil, nilHash[:], nil, signers1, nil},                                    // Very first mutation, empty commitment, working case
		{key, nil, entryData1, nil, nilHash[:], nil, signers1, nil},                                        // Very first mutation, working case
		{key, entryData1, entryData2, nilHash[:], hashEntry1[:], signers1, signers1, nil},                  // Second mutation, working case
		// Test missing keys and signature cases.
		{key, nil, missingKeyEntryData1, nil, nilHash[:], nil, signers1, mutator.ErrMissingKey},                                 // Very first mutation, missing current key
		{key, nil, entryData1, nil, nilHash[:], nil, []signatures.Signer{}, mutator.ErrInvalidSig},                              // Very first mutation, missing current signature
		{key, missingKeyEntryData1, entryData2, nilHash[:], hashMissingKeyEntry1[:], signers1, signers3, mutator.ErrInvalidSig}, // Second mutation, Missing previous authorized key
		{key, entryData1, entryData2, nilHash[:], hashEntry1[:], signers1, signers2, mutator.ErrInvalidSig},                     // Second mutation, missing previous signature
		{key, entryData1, missingKeyEntryData2, nilHash[:], hashEntry1[:], signers1, signers3, nil},                             // Second mutation, missing current authorized key
		{key, entryData1, entryData2, nilHash[:], hashEntry1[:], signers1, signers3, nil},                                       // Second mutation, missing current signature, should work
	} {
		// Create SignedKV from oldEntry:
		firstVal, err := prepareSignedKV(tc.key, tc.oldEntry, tc.oldPrev, tc.oldSigners)
		if err != nil {
			t.Fatalf("%d prepareMutation(%v, %v, %v)=%v", i, tc.key, tc.newEntry, tc.oldPrev, err)
		}
		var oldLeaf []byte
		if tc.oldEntry != nil {
			oldLeaf, err = proto.Marshal(firstVal)
			if err != nil {
				t.Fatalf("proto.Marshal(%v)=%v", firstVal, err)
			}
		}
		// Prepare mutations.
		mutation, err := prepareSignedKV(tc.key, tc.newEntry, tc.newPrev, tc.newSigners)
		if err != nil {
			t.Fatalf("prepareMutation(%v, %v, %v)=%v", tc.key, tc.newEntry, tc.oldPrev, err)
		}

		if _, got := New().Mutate(oldLeaf, mutation); got != tc.err {
			t.Errorf("%d Mutate(%v, %v)=%v, want %v", i, firstVal, mutation, got, tc.err)
		}
	}
}

func TestFromLeafValue(t *testing.T) {
	entry := &tpb.Entry{Commitment: []byte{1, 2}}
	entryB, _ := proto.Marshal(entry)
	skv, _ := proto.Marshal(&tpb.SignedKV{
		KeyValue: &tpb.KeyValue{
			Key:   []byte("someKey"),
			Value: entryB,
		},
	})
	for i, tc := range []struct {
		leafVal []byte
		want    *tpb.Entry
		wantErr bool
	}{
		{[]byte{}, &tpb.Entry{}, false},          // empty leaf bytes -> return 'empty' proto, no error
		{nil, nil, false},                        // non-existing leaf -> return nil, no error
		{[]byte{2, 2, 2, 2, 2, 2, 2}, nil, true}, // no valid proto Message
		{skv, entry, false},                      // valid leaf
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
