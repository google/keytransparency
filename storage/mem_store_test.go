// Copyright 2015 Google Inc. All Rights Reserved.
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

package storage

import (
	"testing"
	"reflect"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
)

type Env struct {
	store *MemStorage
	ctx context.Context
}

// NewEnv sets up common resources for the tests.
func NewEnv(t *testing.T) *Env {
	// Reset current to 0. This only happens while testing.
	current = StartingCommitmentTimestamp
	ctx := context.Background()
	return &Env{CreateMem(ctx), ctx}
}

// populateStorage filles the MemStorage instance with dummy entries.
func (env *Env) populateStorage(t *testing.T) {
	for i := 0; i < 10; i++ {
		entryStorage := &corepb.EntryStorage{}
		if err := env.store.Write(env.ctx, entryStorage); err != nil {
			t.Fatalf("Error while writing to MemStorage: %v", err)
		}
		AdvanceCommitmentTimestamp()
	}
}

func TestRead(t *testing.T) {
	env := NewEnv(t)
	env.populateStorage(t)

	var tests = []struct{
		commitmentTS uint64
		code codes.Code
	}{
		{0, codes.OK},
		{5, codes.OK},
		{9, codes.OK},
		{20, codes.NotFound},
	}

	for i, test := range(tests) {
		_, err := env.store.Read(env.ctx, test.commitmentTS)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: Read(_, %v)=%v, want %v", i, test.commitmentTS, got, want)
		}
	}
}

func TestReadRange(t *testing.T) {
	env := NewEnv(t)
	env.populateStorage(t)

	var tests = []struct{
		startCommitmentTS uint64
		size int32
		outTimestamps []uint64
		code codes.Code
	}{
		// No size specified.
		{0, 0, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, codes.OK},
		// Limited size.
		{0, 10, []uint64{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, codes.OK},
		{2, 7, []uint64{2, 3, 4, 5, 6, 7, 8}, codes.OK},
		{5, 10, []uint64{5, 6, 7, 8, 9}, codes.OK},
		// Should return an empty list storage entries.
		{20, 5, []uint64{}, codes.OK},
	}

	for i, test := range(tests) {
		result, err := env.store.ReadRange(env.ctx, test.startCommitmentTS, test.size)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: ReadRange(_, %v, %v)=%v, want %v", i, test.startCommitmentTS, test.size, got, want)
			return
		}
		if got, want := len(result), len(test.outTimestamps); got != want {
			t.Errorf("Test[%v]: len(ReadRange(_, %v, %v))=%v, want %v", i, test.startCommitmentTS, test.size, got, want)
		}

		// Ensure the returned storage entries have the expected
		// commitment timestamps
		timestamps := make([]uint64, len(result))
		for i, entryStorage := range(result) {
			timestamps[i] = entryStorage.CommitmentTimestamp
		}
		if got, want := timestamps, test.outTimestamps; !reflect.DeepEqual(got, want) {
			t.Errorf("Test[%v]: ReadRange(_, %v, %v)=%v, want %v", i, test.startCommitmentTS, test.size, got, want)
		}
	}
}

func TestSort(t *testing.T) {
	var tests = []struct{
		a []uint64
		output []uint64
	}{
		{[]uint64{1, 2, 3, 4, 5}, []uint64{1, 2, 3, 4, 5}},
		{[]uint64{5, 4, 3, 2, 1}, []uint64{1, 2, 3, 4, 5}},
		{[]uint64{4, 7, 2, 6, 1, 10, 3}, []uint64{1, 2, 3, 4, 6, 7, 10}},
	}

	for i, test := range(tests) {
		sortUint64(test.a)
		if got, want := test.a, test.output; !reflect.DeepEqual(got, want) {
			t.Errorf("Test[%v]: sortUint64 = %v, want: %v", i, got, want)
		}
	}
}
