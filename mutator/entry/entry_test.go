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
	"fmt"
	"testing"

	"github.com/benlaurie/objecthash/go/objecthash"
	"github.com/golang/protobuf/proto"
	"github.com/google/key-transparency/mutator"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

func createEntry(commitment []byte) ([]byte, error) {
	// TODO: fill Commitment and AuthorizedKeys.
	entry := &pb.Entry{
		Commitment: commitment,
	}
	entryData, err := proto.Marshal(entry)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", entry, err)
	}
	return entryData, nil
}

func prepareMutation(key []byte, entryData []byte, previous []byte) ([]byte, error) {
	kv := &pb.KeyValue{
		Key:   key,
		Value: entryData,
	}
	kvData, err := proto.Marshal(kv)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", kv, err)
	}
	skv := &pb.SignedKV{
		KeyValue: kvData,
		Previous: previous,
	}
	mutation, err := proto.Marshal(skv)
	if err != nil {
		return nil, fmt.Errorf("Marshal(%v)=%v", skv, err)
	}
	return mutation, nil
}

func TestCheckMutation(t *testing.T) {
	// The passed commitment to createEntry is a dummy value. It is needed to
	// make the two entries (entryData1 and entryData2) different, otherwise
	// it is not possible to test all cases.
	entryData1, err := createEntry([]byte{1})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	entryData2, err := createEntry([]byte{2})
	if err != nil {
		t.Fatalf("createEntry()=%v", err)
	}
	key := []byte{0}
	largeKey := bytes.Repeat(key, mutator.MaxMutationSize)

	// Calculate hashes.
	hashEntry1 := objecthash.ObjectHash(entryData1)
	// nilHash is used as the previous hash value when submitting the very
	// first mutation.
	nilHash := objecthash.ObjectHash(nil)

	tests := []struct {
		key       []byte
		oldValue  []byte
		entryData []byte
		previous  []byte
		err       error
	}{
		// TODO: test case for verifying signature from key in entry.
		{key, entryData2, entryData2, hashEntry1[:], mutator.ErrReplay},    // Replayed mutation
		{largeKey, entryData1, entryData2, hashEntry1[:], mutator.ErrSize}, // Large mutation
		{key, entryData1, entryData2, nil, mutator.ErrPreviousHash},        // Invalid previous entry hash
		{key, nil, entryData1, nil, mutator.ErrPreviousHash},               // Very first mutation, invalid previous entry hash
		{key, nil, nil, nil, mutator.ErrReplay},                            // Very first mutation, replayed mutation
		{key, nil, entryData1, nilHash[:], nil},                            // Very first mutation, working case
		{key, entryData1, entryData2, hashEntry1[:], nil},                  // Working case
	}

	for i, tc := range tests {
		// Prepare mutations.
		mutation, err := prepareMutation(tc.key, tc.entryData, tc.previous)
		if err != nil {
			t.Fatalf("prepareMutation(%v, %v, %v)=%v", tc.key, tc.entryData, tc.previous, err)
		}

		if got := New().CheckMutation(tc.oldValue, mutation); got != tc.err {
			t.Errorf("%v: CheckMutation(%v, %v)=%v, want %v", i, tc.oldValue, mutation, got, tc.err)
		}
	}
}
