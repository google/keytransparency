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
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/testutil"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/google/tink/go/tink"

	tpb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

func mustObjectHash(t *testing.T, val interface{}) [sha256.Size]byte {
	t.Helper()
	j, err := objecthash.CommonJSONify(val)
	if err != nil {
		t.Fatalf("CommonJSONify() err=%v", err)
	}
	h, err := objecthash.ObjectHash(j)
	if err != nil {
		t.Fatalf("ObjectHash() err=%v", err)
	}
	return h
}

func TestCheckMutation(t *testing.T) {
	// The passed commitment to createEntry is a dummy value. It is needed to
	// make the two entries (entryData1 and entryData2) different, otherwise
	// it is not possible to test all cases.
	key := []byte{0}
	nilHash := mustObjectHash(t, nil)

	entryData1 := &tpb.Entry{
		Index:          key,
		Commitment:     []byte{1},
		AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset(),
		Previous:       nilHash[:],
	}
	hashEntry1 := mustObjectHash(t, *entryData1)

	entryData2 := &tpb.Entry{
		Index:          key,
		Commitment:     []byte{2},
		AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
		Previous:       hashEntry1[:],
	}

	for _, tc := range []struct {
		desc     string
		mutation *Mutation
		signers  []*tink.KeysetHandle
		old      *tpb.Entry
		err      error
	}{
		{
			desc: "Very first mutation, working case",
			old:  nil,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       nilHash[:],
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey1).Keyset(),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1),
		},
		{
			desc: "Second mutation, working case",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1, testPrivKey2),
		},
		{
			desc: "Replayed mutation",
			old:  entryData2,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
				},
			},
			err: mutator.ErrReplay,
		},
		{
			desc: "Large mutation",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index: bytes.Repeat(key, mutator.MaxMutationSize),
				},
			},
			err: mutator.ErrSize,
		},
		{
			desc: "Invalid previous entry hash",
			old:  entryData2,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       nil,
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
				},
			},
			err: mutator.ErrPreviousHash,
		},
		{
			desc: "Very first mutation, invalid previous entry hash",
			mutation: &Mutation{
				entry: &tpb.Entry{
					Previous: nil,
				},
			},
			err: mutator.ErrPreviousHash,
		},
		{
			desc: "Very first mutation, missing previous signature",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey2),
			err:     mutator.ErrUnauthorized,
		},
		{
			desc: "Very first mutation, successful key change",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: testutil.VerifyKeysetFromPEMs(testPubKey2).Keyset(),
				},
			},
			signers: testutil.SignKeysetsFromPEMs(testPrivKey1),
		},
	} {
		m, err := tc.mutation.sign(tc.signers)
		if err != nil {
			t.Errorf("mutation.sign(%v): %v", tc.signers, err)
			continue
		}

		if _, got := New().Mutate(tc.old, m); got != tc.err {
			t.Errorf("%v Mutate(): %v, want %v", tc.desc, got, tc.err)
		}
	}
}
