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

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

func TestCheckMutation(t *testing.T) {
	// The passed commitment to createEntry is a dummy value. It is needed to
	// make the two entries (entryData1 and entryData2) different, otherwise
	// it is not possible to test all cases.
	key := []byte{0}
	nilHash := objecthash.ObjectHash(nil)

	entryData1 := &tpb.Entry{
		Index:          key,
		Commitment:     []byte{1},
		AuthorizedKeys: mustPublicKeys([]string{testPubKey1}),
		Previous:       nilHash[:],
	}
	hashEntry1 := objecthash.ObjectHash(entryData1)

	entryData2 := &tpb.Entry{
		Index:          key,
		Commitment:     []byte{2},
		AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
		Previous:       hashEntry1[:],
	}

	for _, tc := range []struct {
		desc     string
		mutation *Mutation
		signers  []signatures.Signer
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
					AuthorizedKeys: mustPublicKeys([]string{testPubKey1}),
				},
			},
			signers: signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)}),
		},
		{
			desc: "Second mutation, working case",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
				},
			},
			signers: signersFromPEMs(t, [][]byte{[]byte(testPrivKey1), []byte(testPrivKey2)}),
		},
		{
			desc: "Replayed mutation",
			old:  entryData2,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
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
					AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
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
			desc: "Very first mutation, missing current key",
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       nilHash[:],
					AuthorizedKeys: mustPublicKeys([]string{}),
				},
			},
			err:     mutator.ErrMissingKey,
			signers: signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)}),
		},
		{
			desc: "Very first mutation, missing current signature",
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       nilHash[:],
					AuthorizedKeys: mustPublicKeys([]string{testPubKey1}),
				},
			},
			signers: signersFromPEMs(t, [][]byte{}),
			err:     mutator.ErrUnauthorized,
		},
		{
			desc: "Very first mutation, missing previous signature",
			old:  entryData1,
			mutation: &Mutation{
				entry: &tpb.Entry{
					Index:          key,
					Commitment:     []byte{2},
					Previous:       hashEntry1[:],
					AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
				},
			},
			signers: signersFromPEMs(t, [][]byte{[]byte(testPrivKey2)}),
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
					AuthorizedKeys: mustPublicKeys([]string{testPubKey2}),
				},
			},
			signers: signersFromPEMs(t, [][]byte{[]byte(testPrivKey1)}),
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
