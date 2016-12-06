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
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/google/key-transparency/core/mutator"
	"github.com/google/key-transparency/core/signatures"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/proto"

	"github.com/google/key-transparency/core/proto/ctmap"
	tpb "github.com/google/key-transparency/core/proto/keytransparency_v1_types"
)

var (
	errUnimplemented = errors.New("method is unimplemented")
)

// Entry defines mutations to simply replace the current map value with the
// contents of the mutation.
type Entry struct{}

// New creates a new entry mutator.
func New() *Entry {
	return &Entry{}
}

// CheckMutation verifies that this is a valid mutation for this item.
func (*Entry) CheckMutation(oldValue, mutation []byte) error {
	update := new(tpb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		return err
	}

	// Ensure that the mutaiton size is within bounds.
	if proto.Size(update) > mutator.MaxMutationSize {
		return mutator.ErrSize
	}

	// Verify pointer to previous data.
	// The very first entry will have oldValue=nil, so its hash is the
	// ObjectHash value of nil.
	prevEntryHash := objecthash.ObjectHash(oldValue)
	if !bytes.Equal(prevEntryHash[:], update.Previous) {
		// Check if this mutation is a replay.
		if bytes.Equal(oldValue, update.GetKeyValue().Value) {
			return mutator.ErrReplay
		}

		return mutator.ErrPreviousHash
	}

	kv := update.GetKeyValue()
	entry := new(tpb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		return err
	}

	// Ensure that the mutation has at least one authorized key to prevent
	// account lockout.
	if len(entry.GetAuthorizedKeys()) == 0 {
		return mutator.ErrMissingKey
	}

	// Verify authorized keys and signatures based on the following rules:
	//   1. At least one signature with a key in the previous entry exists,
	//      except for the very first update.
	//   2. All new authorized keys should have valid signatures.
	//   3. Signatures with no matching keys are simply ignored.

	// Verify previous keys and signatures if previous entry exists.
	prevEntry := new(tpb.Entry)
	var prevVerifiers map[string]*signatures.Verifier
	if oldValue != nil {
		if err := proto.Unmarshal(oldValue, prevEntry); err != nil {
			return err
		}
		var err error
		prevVerifiers, err = verifiersFromKeys(prevEntry.GetAuthorizedKeys())
		if err != nil {
			return err
		}
		if err := verifyAuthorizedKeys(kv, prevVerifiers, update.Signatures); err != nil {
			return err
		}
	}

	// Verify new authorized keys.
	currentVerifiers, err := verifiersFromKeys(entry.GetAuthorizedKeys())
	if err != nil {
		return err
	}
	newVerifiers := setDifference(prevVerifiers, currentVerifiers)
	if err := verifyNewAuthorizedKeys(kv, newVerifiers, update.Signatures); err != nil {
		return err
	}

	return nil
}

// verifiersFromKeys creates verifier objects from a set of public keys.
// TODO: move the next two functions to the signature library once we can support
//       multiple algorithms.
func verifiersFromKeys(keys []*tpb.PublicKey) (map[string]*signatures.Verifier, error) {
	verifiers := make(map[string]*signatures.Verifier)
	for _, key := range keys {
		verifier, err := verifierFromKey(key)
		if err != nil {
			return nil, err
		}
		verifiers[verifier.KeyName] = verifier
	}
	return verifiers, nil
}

func verifierFromKey(key *tpb.PublicKey) (*signatures.Verifier, error) {
	switch {
	case key.GetEd25519() != nil:
		return nil, errUnimplemented
	case key.GetRsaVerifyingSha256_3072() != nil:
		return nil, errUnimplemented
	case key.GetEcdsaVerifyingP256() != nil:
		k, err := x509.ParsePKIXPublicKey(key.GetEcdsaVerifyingP256())
		if err != nil {
			return nil, err
		}
		return signatures.NewVerifier(k)
	default:
		return nil, errors.New("public key not found")
	}
}

// verifyAuthorizedKeys requires AT LEAST one verifier to have a valid
// corresponding signature.
func verifyAuthorizedKeys(data interface{}, verifiers map[string]*signatures.Verifier, sigs map[string]*ctmap.DigitallySigned) error {
	for _, verifier := range verifiers {
		if sig, ok := sigs[verifier.KeyName]; ok {
			if err := verifier.Verify(data, sig); err == nil {
				return nil
			}
		}
	}
	return mutator.ErrInvalidSig
}

// setDifference gets all new verifiers that did not previously exist.
func setDifference(prevVerifiers, currentVerifiers map[string]*signatures.Verifier) map[string]*signatures.Verifier {
	newVerifiers := make(map[string]*signatures.Verifier)
	for keyName, verifier := range currentVerifiers {
		if _, ok := prevVerifiers[keyName]; !ok {
			newVerifiers[keyName] = verifier
		}
	}
	return newVerifiers
}

// verifyNewAuthorizedKeys requires that ALL verifiers to have valid
// corresponding signatures.
func verifyNewAuthorizedKeys(data interface{}, verifiers map[string]*signatures.Verifier, sigs map[string]*ctmap.DigitallySigned) error {
	for _, verifier := range verifiers {
		sig, ok := sigs[verifier.KeyName]
		if !ok {
			return mutator.ErrInvalidSig
		}
		if verifier.Verify(data, sig) != nil {
			return mutator.ErrInvalidSig
		}
	}
	return nil
}

// Mutate applies mutation to value.
func (*Entry) Mutate(value, mutation []byte) ([]byte, error) {
	update := new(tpb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		return nil, fmt.Errorf("Error unmarshaling update: %v", err)
	}
	return update.GetKeyValue().Value, nil
}
