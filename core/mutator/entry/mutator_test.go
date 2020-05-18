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
	"crypto/sha256"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/testutil"

	tpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

func mustMarshal(t *testing.T, p proto.Message) []byte {
	t.Helper()
	data, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("proto.Marshal(%#v): %v", p, err)
	}
	return data
}

func keysetBytes(pubPEMs ...string) []byte {
	handle := testutil.VerifyKeysetFromPEMs(pubPEMs...)
	var b bytes.Buffer
	if err := handle.WriteWithNoSecrets(keyset.NewBinaryWriter(&b)); err != nil {
		panic(fmt.Sprintf("%v", err))
	}
	return b.Bytes()
}

func TestCheckMutation(t *testing.T) {
	// The passed commitment to createEntry is a dummy value. It is needed to
	// make the two entries (entryData1 and entryData2) different, otherwise
	// it is not possible to test all cases.
	key := []byte{0}

	entryData1 := &tpb.Entry{
		Index:            key,
		Commitment:       []byte{1},
		AuthorizedKeyset: keysetBytes(testPubKey1),
	}
	signedEntryData1 := &tpb.SignedEntry{
		Entry: mustMarshal(t, entryData1),
	}

	hashEntry1 := sha256.Sum256(signedEntryData1.Entry)
	entryData2 := &tpb.Entry{
		Index:            key,
		Commitment:       []byte{2},
		AuthorizedKeyset: keysetBytes(testPubKey2),
	}
	signedEntryData2 := &tpb.SignedEntry{
		Entry: mustMarshal(t, entryData2),
	}

	for _, tc := range []struct {
		desc     string
		mutation *Mutation
		signers  []tink.Signer
		old      *tpb.SignedEntry
		err      error
	}{
		{
			desc: "Very first mutation, working case",
			old:  nil,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					AuthorizedKeyset: keysetBytes(testPubKey1),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1),
		},
		{
			desc: "Second mutation, working case",
			old:  signedEntryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					Previous:         hashEntry1[:],
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2),
		},
		{
			desc: "Replayed mutation",
			old:  signedEntryData2,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2),
			err:     mutator.ErrReplay,
		},
		{
			desc: "Large mutation",
			old:  signedEntryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index: bytes.Repeat(key, mutator.MaxMutationSize),
				},
			},
			err: mutator.ErrSize,
		},
		{
			desc: "Invalid previous entry hash",
			old:  signedEntryData2,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					Previous:         []byte("invalidhash"),
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2),
			err:     mutator.ErrPreviousHash,
		},
		{
			desc: "Very first mutation, invalid previous entry hash",
			mutation: &Mutation{
				entry: &tpb.Entry{
					Previous:         []byte("invalidhash"),
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey2),
			err:     mutator.ErrPreviousHash,
		},
		{
			desc: "Very first mutation, missing previous signature",
			old:  signedEntryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey2),
			err:     mutator.ErrUnauthorized,
		},
		{
			desc: "Very first mutation, successful key change",
			old:  signedEntryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:            key,
					Commitment:       []byte{2},
					AuthorizedKeyset: keysetBytes(testPubKey2),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2),
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			m, err := tc.mutation.sign(tc.signers)
			if err != nil {
				t.Fatalf("mutation.sign(%v): %v", tc.signers, err)
			}
			if _, got := MutateFn(tc.old, m); got != tc.err {
				t.Errorf("%v Mutate(): %v, want %v", tc.desc, got, tc.err)
			}
		})
	}
}
