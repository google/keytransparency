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
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	corepb "github.com/google/e2e-key-server/proto/google_security_e2ekeys_core"
	ctmap "github.com/google/e2e-key-server/proto/security_ctmap"
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
	invalidIndex *ctmap.SignedEntryUpdate
	// Contains a signed entry update with invalid entry.
	invalidEntry *ctmap.SignedEntryUpdate
	// Contains a valid signed entry update
	validEntryUpdate *ctmap.SignedEntryUpdate
}

func NewEnv(t *testing.T) *Env {
	b := New(&Fake_Distributed{}, nil)
	b.ListenForEpochUpdates()
	updates := GenerateEntryUpdates(t)

	return &Env{b, updates}
}

func (env *Env) Close() {
	env.b.Close()
}

func GenerateEntryUpdates(t *testing.T) *EntryUpdates {
	// Generate a signed entry update with an invalid index length. This is
	// done by using part of the index, e.g. first 10 bytes.
	invalidEntryBytes, err := proto.Marshal(&ctmap.Entry{Index: testUserIndex[:10]})
	if err != nil {
		t.Fatalf("Unexpected entry marshalling error %v.", err)
	}
	invalidIndex := &ctmap.SignedEntryUpdate{NewEntry: invalidEntryBytes}

	// Generate a signed entry update with an invalid entry. This is done by
	// using part of the valid entry update in the signed entry update, e.g.
	// all bytes except the first one.
	validEntryBytes, err := proto.Marshal(&ctmap.Entry{Index: testUserIndex})
	if err != nil {
		t.Fatalf("Unexpected entry marshalling error %v.", err)
	}
	invalidEntry := &ctmap.SignedEntryUpdate{NewEntry: validEntryBytes[1:]}

	// Generate a valid signed entry update.
	validEntryUpdate := &ctmap.SignedEntryUpdate{NewEntry: validEntryBytes}

	return &EntryUpdates{invalidIndex, invalidEntry, validEntryUpdate}
}

func TestPost(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close()

	m := merkle.New()
	tests := []struct {
		entryUpdate *ctmap.SignedEntryUpdate
		code        codes.Code
	}{
		{env.updates.validEntryUpdate, codes.OK},
		{env.updates.invalidEntry, codes.Internal},
		{env.updates.invalidIndex, codes.InvalidArgument},
	}

	for i, test := range tests {
		es := &corepb.EntryStorage{
			SignedEntryUpdate: test.entryUpdate,
		}
		err := env.b.post(m, es)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: post()=%v, want %v, %v", i, got, want, err)
		}
	}
}

// Implementing mock static db.
type Fake_Distributed struct {
}

func (s *Fake_Distributed) ReadUpdate(ctx context.Context, primaryKey int64) (*corepb.EntryStorage, error) {
	return nil, nil
}

func (s *Fake_Distributed) ReadEpochInfo(ctx context.Context, primaryKey int64) (*corepb.EpochInfo, error) {
	return nil, nil
}

func (s *Fake_Distributed) WriteUpdate(ctx context.Context, entry *corepb.EntryStorage) error {
	return nil
}

func (s *Fake_Distributed) WriteEpochInfo(ctx context.Context, primaryKey int64, epochInfo *corepb.EpochInfo) error {
	return nil
}

func (s *Fake_Distributed) SubscribeUpdates(ch chan *corepb.EntryStorage) {
}

func (s *Fake_Distributed) SubscribeEpochInfo(ch chan *corepb.EpochInfo) {
}
