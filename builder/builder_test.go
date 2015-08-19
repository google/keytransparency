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

package builder

import (
	"encoding/hex"
	"testing"

	"github.com/google/e2e-key-server/merkle"
	"github.com/google/e2e-key-server/storage"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	corepb "github.com/google/e2e-key-server/proto/core"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

var (
	// Mock user index, no need to use the real one.
	testUserIndex, _ = hex.DecodeString("0000000000000000000000000000000000000000000000000000000000000000")
)

type Env struct {
	b       *Builder
	updates *EntryUpdates
}

type EntryUpdates struct {
	// Contains a signed entry update with a short index.
	invalidIndex []byte
	// Contains a signed entry update with invalid entry.
	invalidEntry []byte
	// Contains a valid signed entry update
	validEntryUpdate []byte
}

func NewEnv(t *testing.T) *Env {
	b := New(nil, Fake_SaveCommitmentIndexAndEpoch)
	updates := GenerateEntryUpdates(t)

	return &Env{b, updates}
}

func GenerateEntryUpdates(t *testing.T) *EntryUpdates {
	// Generate a signed entry update with an invalid index length. This is
	// done by using part of the index, e.g. first 10 bytes.
	invalidEntryBytes, err := proto.Marshal(&v2pb.Entry{Index: testUserIndex[:10]})
	if err != nil {
		t.Fatalf("Unexpected entry marshalling error %v.", err)
	}
	invalidIndex, _ := proto.Marshal(&v2pb.SignedEntryUpdate{Entry: invalidEntryBytes})

	// Generate a signed entry update with an invalid entry. This is done by
	// using part of the valid entry update in the signed entry update, e.g.
	// all bytes except the first one.
	validEntryBytes, err := proto.Marshal(&v2pb.Entry{Index: testUserIndex})
	if err != nil {
		t.Fatalf("Unexpected entry marshalling error %v.", err)
	}
	invalidEntry, _ := proto.Marshal(&v2pb.SignedEntryUpdate{Entry: validEntryBytes[1:]})

	// Generate a valid signed entry update.
	validEntryUpdate, _ := proto.Marshal(&v2pb.SignedEntryUpdate{Entry: validEntryBytes})

	return &EntryUpdates{invalidIndex, invalidEntry, validEntryUpdate}
}

func TestPost(t *testing.T) {
	env := NewEnv(t)
	m := merkle.New()
	tests := []struct {
		entryUpdate []byte
		code        codes.Code
	}{
		{env.updates.validEntryUpdate, codes.OK},
		// Taking the first 10 (or any number of, except all) bytes of
		// the valid entry update simulate a broken entry update that
		// cannot be unmarshaled.
		{env.updates.validEntryUpdate[:10], codes.Internal},
		{env.updates.invalidEntry, codes.Internal},
		{env.updates.invalidIndex, codes.InvalidArgument},
	}

	for i, test := range tests {
		es := &corepb.EntryStorage{
			EntryUpdate: test.entryUpdate,
		}
		err := env.b.post(m, es)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: post()=%v, want %v, %v", i, got, want, err)
		}
	}
}

func Fake_SaveCommitmentIndexAndEpoch(index string, epoch merkle.Epoch, commitment storage.CommitmentTimestamp) error {
	return nil
}
