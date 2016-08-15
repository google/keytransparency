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

// Package entry implements a simple replacement stragey as a mapper
package entry

import (
	"bytes"
	"fmt"

	"github.com/google/key-transparency/core/mutator"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/proto"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
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
	update := new(pb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		return err
	}

	// Ensure that the mutaiton size is within bounds.
	if proto.Size(update) > mutator.MaxMutationSize {
		return mutator.ErrSize
	}

	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(update.KeyValue, kv); err != nil {
		return err
	}

	// Verify pointer to previous data.
	// The very first entry will have oldValue=nil, so its hash is the
	// ObjectHash value of nil.
	prevEntryHash := objecthash.ObjectHash(oldValue)
	if !bytes.Equal(prevEntryHash[:], update.Previous) {
		// Check if this mutation is a replay.
		if bytes.Equal(oldValue, kv.Value) {
			return mutator.ErrReplay
		}

		return mutator.ErrPreviousHash
	}

	entry := new(pb.Entry)
	if err := proto.Unmarshal(kv.Value, entry); err != nil {
		return err
	}

	// TODO: Verify signature from key in entry.

	return nil
}

// Mutate applies mutation to value.
func (*Entry) Mutate(value, mutation []byte) ([]byte, error) {
	update := new(pb.SignedKV)
	if err := proto.Unmarshal(mutation, update); err != nil {
		return nil, fmt.Errorf("Error unmarshaling update: %v", err)
	}
	kv := new(pb.KeyValue)
	if err := proto.Unmarshal(update.KeyValue, kv); err != nil {
		return nil, fmt.Errorf("Error unmarshaling keyvalue: %v", err)
	}

	return kv.Value, nil
}
