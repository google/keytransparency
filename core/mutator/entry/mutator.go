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
	"fmt"

	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/mutator"

	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/crypto/sigpb"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
)

// Mutator defines mutations to simply replace the current map value with the
// contents of the mutation.
type Mutator struct{}

// New creates a new entry mutator.
func New() *Mutator {
	return &Mutator{}
}

// Mutate verifies that this is a valid mutation for this item and applies
// mutation to value. Repeated applications of Mutate on the same input produce
// the same output. OldValue and update are both SignedKV protos.
func (*Mutator) Mutate(oldValue, update proto.Message) (proto.Message, error) {
	// Ensure that the mutation size is within bounds.
	if proto.Size(update) > mutator.MaxMutationSize {
		glog.Warningf("mutation (%v bytes) is larger than the maximum accepted size (%v bytes).", proto.Size(update), mutator.MaxMutationSize)
		return nil, mutator.ErrSize
	}

	newEntry, ok := update.(*pb.Entry)
	if !ok {
		glog.Warning("received proto.Message is not of type *pb.Entry.")
		return nil, fmt.Errorf("updateM.(*pb.Entry): _, %v", ok)
	}
	var oldEntry *pb.Entry
	if oldValue != nil {
		old, ok := oldValue.(*pb.Entry)
		if !ok {
			glog.Warning("received proto.Message is not of type *pb.Entry.")
			return nil, fmt.Errorf("oldValueM.(*pb.Entry): _, %v", ok)
		}
		oldEntry = old
	}

	// Verify pointer to previous data.  The very first entry will have
	// oldValue=nil, so its hash is the ObjectHash value of nil.
	oej, err := objecthash.CommonJSONify(oldEntry)
	if err != nil {
		return nil, fmt.Errorf("CommonJSONify: %v", err)
	}
	prevEntryHash, err := objecthash.ObjectHash(oej)
	if err != nil {
		return nil, fmt.Errorf("ObjectHash: %v", err)
	}

	if !bytes.Equal(prevEntryHash[:], newEntry.GetPrevious()) {
		// Check if this mutation is a replay.
		if oldEntry != nil && proto.Equal(oldEntry, newEntry) {
			glog.Warningf("mutation is a replay of an old one")
			return nil, mutator.ErrReplay
		}
		glog.Warningf("previous entry hash (%v) does not match the hash provided in this mutation (%v)", prevEntryHash[:], newEntry.GetPrevious())
		return nil, mutator.ErrPreviousHash
	}

	// Ensure that the mutation has at least one authorized key to prevent
	// account lockout.
	if len(newEntry.GetAuthorizedKeys()) == 0 {
		glog.Warningf("mutation should contain at least one authorized key")
		return nil, mutator.ErrMissingKey
	}

	kv := *newEntry
	kv.Signatures = nil
	if err := verifyKeys(oldEntry.GetAuthorizedKeys(),
		newEntry.GetAuthorizedKeys(),
		kv,
		newEntry.GetSignatures(),
	); err != nil {
		return nil, err
	}

	return newEntry, nil
}

// verifyKeys verifies both old and new authorized keys based on the following
// criteria:
//   1. At least one signature with a key in the previous entry should exist.
//   2. If prevAuthz is nil, at least one signature with a key from the new
//   authorized_key set should exist.
//   3. Signatures with no matching keys are simply ignored.
func verifyKeys(prevAuthz, authz []*keyspb.PublicKey, data interface{}, sigs map[string]*sigpb.DigitallySigned) error {
	var verifiers map[string]signatures.Verifier
	var err error
	if prevAuthz == nil {
		verifiers, err = verifiersFromKeys(authz)
		if err != nil {
			return err
		}
	} else {
		verifiers, err = verifiersFromKeys(prevAuthz)
		if err != nil {
			return err
		}
	}

	return verifyAuthorizedKeys(data, verifiers, sigs)
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
	return mutator.ErrUnauthorized
}
