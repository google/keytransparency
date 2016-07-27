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

func prepareTest(key []byte, entry *pb.Entry) (mutation []byte, entryData []byte, err error) {
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
	skv := &pb.SignedKV{KeyValue: kvData}
	mutation, err = proto.Marshal(skv)
	if err != nil {
		return nil, nil, fmt.Errorf("Marshal(%v)=%v", skv, err)
	}
	return mutation, entryData, nil
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

	mutation1, entryData1, err := prepareTest(key, entry1)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry1, err)
	}
	largeMutation, _, err := prepareTest(bytes.Repeat(key, mutator.MaxMutationSize), entry2)
	if err != nil {
		t.Fatalf("prepareTest(%v, %v)=%v", key, entry2, err)
	}

	tests := []struct {
		oldValue []byte
		mutation []byte
		err      error
	}{
		{entryData1, mutation1, mutator.ErrReplay},   // Replayed mutation
		{entryData1, largeMutation, mutator.ErrSize}, // Large mutation
		// TODO: test case for verifying pointer to previous data.
		// TODO: test case for verifying signature from key in entry.
	}

	entry := New()
	for i, tc := range tests {
		if got := entry.CheckMutation(tc.oldValue, tc.mutation); got != tc.err {
			t.Errorf("%v: CheckMutation(%v, %v)=%v, want %v", i, tc.oldValue, tc.mutation, got, tc.err)
		}
	}
}
