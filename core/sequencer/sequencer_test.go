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
	"fmt"
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"

	tpb "github.com/google/trillian"
)

func queueMsg(id int64, signer *tink.KeysetHandle) *mutator.QueueMessage {
	index := []byte{byte(id)}
	userID := string(id)
	m := entry.NewMutation(index, "domain", "app", userID)
	signers := []*tink.KeysetHandle{signer}
	pubkey, err := signer.GetPublicKeysetHandle()
	if err != nil {
		panic(fmt.Errorf("GetPublicKeysetHandle(): %v", err))
	}
	m.ReplaceAuthorizedKeys(pubkey.Keyset())
	update, err := m.SerializeAndSign(signers, 0)
	if err != nil {
		panic(fmt.Errorf("SerializeAndSign(): %v", err))
	}

	return &mutator.QueueMessage{
		ID:        id,
		Mutation:  update.EntryUpdate.Mutation,
		ExtraData: update.EntryUpdate.Committed,
	}
}

// TestDuplicateMutations verifies that each call to tlog.SetLeaves specifies
// each mapleaf.Index at most ONCE.  Failure to do so will corrupt the map.
func TestDuplicateMutations(t *testing.T) {

	keyset, err := tink.CleartextKeysetHandle().GenerateNew(signature.EcdsaP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.GenerateNew(): %v", err)
	}
	s := &Sequencer{
		mutatorFunc: entry.New(),
	}

	for _, tc := range []struct {
		desc       string
		msgs       []*mutator.QueueMessage
		leaves     []*tpb.MapLeaf
		wantLeaves int
	}{
		{
			desc: "duplicate",
			msgs: []*mutator.QueueMessage{
				queueMsg(1, keyset),
				queueMsg(1, keyset),
			},
			wantLeaves: 1,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			newLeaves, err := s.applyMutations(tc.msgs, tc.leaves)
			if err != nil {
				t.Errorf("applyMutations(): %v", err)
			}
			// Count unique map leaves.
			counts := make(map[[32]byte]int)
			for _, l := range newLeaves {
				counts[toArray(l.Index)]++
				if c := counts[toArray(l.Index)]; c > 1 {
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
