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

func prepareTest(key []byte, entry *pb.Entry) (skv *pb.SignedKV, entryData []byte, err error) {
	entryData, err = proto.Marshal(entry)
	if err != nil {
		return nil, nil, fmt.Errorf("Marshal(%v)=%v", entry, err)
	}
	kv := &pb.KeyValue{
		Key:   key,
		Value: entryData,
	}
	kvData, err := proto.Marshal(kv)
	if err != nil {
		return nil, nil, fmt.Errorf("Marshal(%v)=%v", kv, err)
	}
	skv = &pb.SignedKV{KeyValue: kvData}
	return skv, entryData, nil
}

func prepareMutation(skv *pb.SignedKV, previous []byte) (mutation []byte, err error) {
	skv.Previous = previous
	return proto.Marshal(skv)
}

func TestCheckMutation(t *testing.T) {
	entry1 := &pb.Entry{
		// TODO: fill Commitment and AuthorizedKeys.
		UpdateCount: 1,
	}
	entry2 := &pb.Entry{
		// TODO: fill Commitment and AuthorizedKeys.
		UpdateCount: 2,
	}
	key := []byte{0}

	skv1, entryData1, err := prepareTest(key, entry1)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry1, err)
	}
	skv2, _, err := prepareTest(key, entry2)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry2, err)
	}
	largeSKV, _, err := prepareTest(bytes.Repeat(key, mutator.MaxMutationSize), entry2)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry2, err)
	}
	selfSKV, _, err := prepareTest(key, entry1)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry1, err)
	}

	// Calculate hashes.
	hashEntry1, err := mutator.ObjectHash(entryData1)
	if err != nil {
		t.Fatalf("ObjectHash(%v)=%v", entryData1, err)
	}

	// Prepare mutations.
	mutation1, err := prepareMutation(skv1, nil)
	if err != nil {
		t.Fatalf("prepareMutation(%v, %v)=%v", skv1, nil, err)
	}
	mutation2, err := prepareMutation(skv2, hashEntry1)
	if err != nil {
		t.Fatalf("prepareMutation(%v, %v)=%v", skv2, hashEntry1, err)
	}
	largeMutation, err := prepareMutation(largeSKV, hashEntry1)
	if err != nil {
		t.Fatalf("prepareMutation(%v, %v)=%v", largeSKV, hashEntry1, err)
	}
	selfMutation, err := prepareMutation(selfSKV, hashEntry1)
	if err != nil {
		t.Fatalf("prepareMutation(%v, %v)=%v", selfSKV, hashEntry1, err)
	}

	tests := []struct {
		oldValue []byte
		mutation []byte
		err      error
	}{
		{entryData1, mutation2, nil},                      // Normal case.
		{entryData1, selfMutation, mutator.ErrReplay},     // Replayed mutation
		{entryData1, largeMutation, mutator.ErrSize},      // Large mutation
		{entryData1, mutation1, mutator.ErrWrongPrevious}, // Wrong previous entry
		// TODO: test case for verifying signature from key in entry.
	}

	entry := New()
	for i, tc := range tests {
		if got := entry.CheckMutation(tc.oldValue, tc.mutation); got != tc.err {
			t.Errorf("%v: CheckMutation(%v, %v)=%v, want %v", i, tc.oldValue, tc.mutation, got, tc.err)
		}
	}
}
