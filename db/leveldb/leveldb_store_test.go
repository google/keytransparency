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

package leveldb

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	corepb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys_core"
	ctmap "github.com/gdbelvin/e2e-key-server/proto/security_ctmap"
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
	epochs = []struct {
		epoch int64
		info  *corepb.EpochInfo
	}{
		{0, &corepb.EpochInfo{
			SignedEpochHead:         &ctmap.SignedEpochHead{},
			LastCommitmentTimestamp: 1,
		}},
		{1, &corepb.EpochInfo{
			SignedEpochHead:         &ctmap.SignedEpochHead{},
			LastCommitmentTimestamp: 2,
		}},
		{3, &corepb.EpochInfo{
			SignedEpochHead:         &ctmap.SignedEpochHead{},
			LastCommitmentTimestamp: 3,
		}},
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
	store, err := Open(tmpPath)
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

func (env *Env) FillEntries(t *testing.T) {
	for i, entry := range entries {
		if got, want := grpc.Code(env.store.WriteUpdate(env.ctx, entry)), codes.OK; got != want {
			t.Fatalf("Entry[%v]: Error while filling updates database, got %v, want %v", i, got, want)
		}
	}
}

func (env *Env) FillEpochs(t *testing.T) {
	for i, v := range epochs {
		if got, want := grpc.Code(env.store.WriteEpochInfo(env.ctx, v.epoch, v.info)), codes.OK; got != want {
			t.Fatalf("Epoch[%v]: Error while filling epochs database, got %v, want %v", i, got, want)
		}
	}
}

func TestReadUpdate(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close(t)

	env.FillEntries(t)

	tests := []struct {
		entry *corepb.EntryStorage
		code  codes.Code
	}{
		{entries[0], codes.OK},
		{entries[1], codes.OK},
		{entries[2], codes.OK},
		{&corepb.EntryStorage{
			CommitmentTimestamp: 4,
			Profile:             []byte{4},
		}, codes.NotFound},
	}

	for i, test := range tests {
		res, err := env.store.ReadUpdate(env.ctx, test.entry.CommitmentTimestamp)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: Error while reading from updates database, got %v, want %v", i, got, want)
		}
		if err != nil {
			continue
		}

		if !reflect.DeepEqual(test.entry.Profile, res.Profile) {
			t.Errorf("Test[%v]: Read entry is not as expected, got %v, want %v", res, test.entry)
		}
	}
}

func TestReadEpochInfo(t *testing.T) {
	t.Parallel()

	env := NewEnv(t)
	defer env.Close(t)

	env.FillEpochs(t)

	tests := []struct {
		epoch int64
		info  *corepb.EpochInfo
		code  codes.Code
	}{
		{epochs[0].epoch, epochs[0].info, codes.OK},
		{epochs[1].epoch, epochs[1].info, codes.OK},
		{epochs[2].epoch, epochs[2].info, codes.OK},
		{4, &corepb.EpochInfo{
			SignedEpochHead:         &ctmap.SignedEpochHead{},
			LastCommitmentTimestamp: 4,
		}, codes.NotFound},
	}

	for i, test := range tests {
		res, err := env.store.ReadEpochInfo(env.ctx, test.epoch)
		if got, want := grpc.Code(err), test.code; got != want {
			t.Errorf("Test[%v]: Error while reading from epochs database, got %v, want %v", i, got, want)
		}
		if err != nil {
			continue
		}

		if got, want := res.LastCommitmentTimestamp, test.info.LastCommitmentTimestamp; got != want {
			t.Errorf("Test[%v]: Read entry is not as expected, got last timestamp %v, want %v", got, want)
		}
	}
}
