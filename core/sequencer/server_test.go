// Copyright 2018 Google Inc. All Rights Reserved.
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

package sequencer

import (
	"testing"

	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"

	ktpb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tpb "github.com/google/trillian"
)

func queueMsg(t *testing.T, id int64, signer *tink.KeysetHandle) *ktpb.EntryUpdate {
	t.Helper()
	index := []byte{byte(id)}
	userID := string(id)
	m := entry.NewMutation(index, "domain", "app", userID)
	signers := []*tink.KeysetHandle{signer}
	pubkey, err := signer.Public()
	if err != nil {
		t.Fatalf("Public(): %v", err)
	}
	if err := m.ReplaceAuthorizedKeys(pubkey.Keyset()); err != nil {
		t.Fatalf("ReplaceAuthorizedKeys(): %v", err)
	}
	update, err := m.SerializeAndSign(signers, 0)
	if err != nil {
		t.Fatalf("SerializeAndSign(): %v", err)
	}

	return &ktpb.EntryUpdate{
		Mutation:  update.EntryUpdate.Mutation,
		Committed: &ktpb.Committed{},
	}
}

// TestDuplicateMutations verifies that each call to tlog.SetLeaves specifies
// each mapleaf.Index at most ONCE.
func TestDuplicateMutations(t *testing.T) {

	keyset1, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.GenerateNew(): %v", err)
	}
	keyset2, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.GenerateNew(): %v", err)
	}
	s := &Server{}

	for _, tc := range []struct {
		desc       string
		msgs       []*ktpb.EntryUpdate
		leaves     []*tpb.MapLeaf
		wantLeaves int
	}{
		{
			desc: "duplicate index, same data",
			msgs: []*ktpb.EntryUpdate{
				queueMsg(t, 1, keyset1),
				queueMsg(t, 1, keyset1),
			},
			wantLeaves: 1,
		},
		{
			desc: "duplicate index, different data",
			msgs: []*ktpb.EntryUpdate{
				queueMsg(t, 1, keyset1),
				queueMsg(t, 1, keyset2),
			},
			wantLeaves: 1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			domainID := "test"
			newLeaves, err := s.applyMutations(domainID, entry.New(), tc.msgs, tc.leaves)
			if err != nil {
				t.Errorf("applyMutations(): %v", err)
			}
			// Count unique map leaves.
			counts := make(map[string]int)
			for _, l := range newLeaves {
				counts[string(l.Index)]++
				if c := counts[string(l.Index)]; c > 1 {
					t.Errorf("Map leaf %x found %v times", l.Index, c)
				}
			}
			// Verify totals.
			if got, want := len(newLeaves), tc.wantLeaves; got != want {
				t.Errorf("applyMutations(): len: %v, want %v", got, want)
			}
		})
	}
}
