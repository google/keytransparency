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
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/google/e2e-key-server/proto/core"
	context "golang.org/x/net/context"
)

var (
	entries = []*corepb.EntryStorage{
		&corepb.EntryStorage{
			CommitmentTimestamp: 1,
			Profile:             []byte{1},
		},
		&corepb.EntryStorage{
			CommitmentTimestamp: 2,
			Profile:             []byte{2},
		},
		&corepb.EntryStorage{
			CommitmentTimestamp: 3,
			Profile:             []byte{3},
		},
	}
)

type Env struct {
	tmpPath string
	store   *LevelDBStorage
	ctx     context.Context
}

func NewEnv(t *testing.T) *Env {
	tmpPath, err := ioutil.TempDir("", "db")
	if err != nil {
		t.Fatalf("Cannot create database tmp directory: %v", err)
	}
	store, err := OpenDB(tmpPath)
	if err != nil {
		t.Fatalf("Error while opening the database: %v", err)
	}

	ctx := context.Background()

	return &Env{tmpPath, store, ctx}
}

func (env *Env) Close(t *testing.T) {
	env.store.Close()

	// Remove database tmp directory.
	if err := os.RemoveAll(env.tmpPath); err != nil {
		t.Fatalf("Cannot remove database tmp directory: %v", err)
	}
}

func (env *Env) FillStore(t *testing.T) {
	for i, entry := range entries {
		if got, want := grpc.Code(env.store.Write(env.ctx, entry)), codes.OK; got != want {
			t.Fatalf("Entry[%v]: Error while filling leveldb store, got %v, want %v", i, got, want)
		}
	}
}

func TestRead(t *testing.T) {
	env := NewEnv(t)
	defer env.Close(t)

	env.FillStore(t)

	tests := []struct {
		entry *corepb.EntryStorage
		code  codes.Code
	}{
		{entries[0], codes.OK},
		{entries[0], codes.OK},
		{entries[0], codes.OK},
		{&corepb.EntryStorage{
			CommitmentTimestamp: 4,
			Profile:             []byte{4},
		}, codes.NotFound},
	}

	for i, test := range tests {
		res, err := env.store.Read(env.ctx, test.entry.CommitmentTimestamp)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: Error while reading from leveldb store, got %v, want %v", i, got, want)
		}
		if err != nil {
			continue
		}

		if !reflect.DeepEqual(test.entry.Profile, res.Profile) {
			t.Errorf("Test[%v]: Read entry is not as expected, got %v, want %v", res, test.entry)
		}
	}
}
