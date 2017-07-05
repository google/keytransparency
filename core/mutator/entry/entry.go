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

// Package entry implements a simple replacement strategy as a mapper.
package entry

import (
	"bytes"

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/mutator"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	"github.com/google/trillian/crypto/sigpb"
)

// Entry defines mutations to simply replace the current map value with the
// contents of the mutation.
type Entry struct{}

// New creates a new entry mutator.
func New() *Entry {
	return &Entry{}
}

// Mutate verifies that this is a valid mutation for this item and applies
// mutation to value.
func (*Entry) Mutate(oldValue, mutation []byte) ([]byte, error) {
	update := new(tpb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		return nil, err
	}

	// Ensure that the mutation size is within bounds.
	if proto.Size(update) > mutator.MaxMutationSize {
		glog.Warningf("mutation (%v bytes) is larger than the maximum accepted size (%v bytes).", proto.Size(update), mutator.MaxMutationSize)
		return nil, mutator.ErrSize
	}

	// Verify pointer to previous data.
	// The very first entry will have oldValue=nil, so its hash is the
	// ObjectHash value of nil.
	prevEntryHash := objecthash.ObjectHash(oldValue)
	if !bytes.Equal(prevEntryHash[:], update.Previous) {
		// Check if this mutation is a replay.
		if bytes.Equal(oldValue, update.GetKeyValue().Value) {
			glog.Warningf("mutation is a replay of an old one")
			return nil, mutator.ErrReplay
		}

		glog.Warningf("previous entry hash (%v) does not match the hash provided in this mutation (%v)", prevEntryHash[:], update.Previous)
		return nil, mutator.ErrPreviousHash
	}

	kv := update.GetKeyValue()
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		return nil, err
	}

	// Ensure that the mutation has at least one authorized key to prevent
	// account lockout.
	if len(entry.GetAuthorizedKeys()) == 0 {
		glog.Warningf("mutation should contain at least one authorized key")
		return nil, mutator.ErrMissingKey
	}

	if err := verifyKeys(oldValue, kv, update, entry); err != nil {
		return nil, err
	}

	return update.GetKeyValue().GetValue(), nil
}

// verifyKeys verifies both old and new authorized keys based on the following
// criteria:
//   1. At least one signature with a key in the previous entry should exist.
//   2. The first mutation should contain at least one signature with a key in
//      in that mutation.
//   3. Signatures with no matching keys are simply ignored.
func verifyKeys(oldValue []byte, data interface{}, update *tpb.SignedKV, entry *tpb.Entry) error {
	prevEntry := new(tpb.Entry)
	var verifiers map[string]signatures.Verifier
	var err error
	if oldValue == nil {
		verifiers, err = verifiersFromKeys(entry.GetAuthorizedKeys())
		if err != nil {
			return err
		}
	} else {
		if err = proto.Unmarshal(oldValue, prevEntry); err != nil {
			return err
		}
		verifiers, err = verifiersFromKeys(prevEntry.GetAuthorizedKeys())
		if err != nil {
			return err
		}
	}

	if err = verifyAuthorizedKeys(data, verifiers, update.Signatures); err != nil {
		return err
	}
	return nil
}

func verifiersFromKeys(keys []*tpb.PublicKey) (map[string]signatures.Verifier, error) {
	verifiers := make(map[string]signatures.Verifier)
	for _, key := range keys {
		verifier, err := factory.NewVerifierFromKey(key)
		if err != nil {
			return nil, err
		}
		verifiers[verifier.KeyID()] = verifier
	}
	return verifiers, nil
}

// verifyAuthorizedKeys requires AT LEAST one verifier to have a valid
// corresponding signature.
func verifyAuthorizedKeys(data interface{}, verifiers map[string]signatures.Verifier, sigs map[string]*sigpb.DigitallySigned) error {
	for _, verifier := range verifiers {
		if sig, ok := sigs[verifier.KeyID()]; ok {
			if err := verifier.Verify(data, sig); err == nil {
				return nil
			}
		}
	}
	return mutator.ErrInvalidSig
}
