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

	"github.com/golang/protobuf/proto"
	"github.com/google/key-transparency/mutator"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

func createEntry(updateCount uint64) ([]byte, error) {
	entry := &pb.Entry{
		// TODO: fill Commitment and AuthorizedKeys.
		UpdateCount: updateCount,
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
	count := uint64(1)
	entryData1, err := createEntry(count)
	if err != nil {
		t.Fatalf("createEntry(%v)=%v", count, err)
	}
	entryData2, err := createEntry(count + 1)
	if err != nil {
		t.Fatalf("createEntry(%v)=%v", count+1, err)
	}
	key := []byte{0}
	largeKey := bytes.Repeat(key, mutator.MaxMutationSize)

	// Calculate hashes.
	hashEntry1, err := mutator.ObjectHash(entryData1)
	if err != nil {
		t.Fatalf("ObjectHash(%v)=%v", entryData1, err)
	}

	tests := []struct {
		key       []byte
		oldValue  []byte
		entryData []byte
		previous  []byte
		err       error
	}{
		{key, entryData1, entryData2, hashEntry1, nil},                  // Normal case.
		{key, entryData1, entryData1, hashEntry1, mutator.ErrReplay},    // Replayed mutation
		{largeKey, entryData1, entryData2, hashEntry1, mutator.ErrSize}, // Large mutation
		{key, entryData1, entryData1, nil, mutator.ErrPreviousHash},     // Invalid previous entry hash
		// TODO: test case for verifying signature from key in entry.
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
