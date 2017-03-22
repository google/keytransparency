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
package mutations

import (
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/impl/sql/testutil"
	_ "github.com/mattn/go-sqlite3"
)

const mapID = 0

func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func fillDB(t *testing.T, ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory) {
	for _, mtn := range []struct {
		epoch    int64
		index    []byte
		mutation []byte
	}{
		{1, []byte("index1"), []byte("mutation1")},
		{2, []byte("index2"), []byte("mutation2")},
	} {
		if err := write(ctx, m, factory, mtn.epoch, mtn.index, mtn.mutation); err != nil {
			t.Errorf("failed to write mutation to database, epoch=%v, mutation=%v, mutation=%v: %v", mtn.epoch, mtn.index, mtn.mutation, err)
		}
	}
}

func write(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, epoch int64, index []byte, mutation []byte) error {
	wtxn, err := factory.NewDBTxn(ctx)
	if err != nil {
		return fmt.Errorf("failed to create write transaction: %v", err)
	}
	if err := m.Write(ctx, wtxn, epoch, index, mutation); err != nil {
		return fmt.Errorf("Write(%v, %v, %v): %v, want nil", epoch, index, mutation, err)
	}
	if err := wtxn.Commit(); err != nil {
		return fmt.Errorf("wtxn.Commit() failed: %v", err)
	}
	return nil
}

func read(ctx context.Context, m mutator.Mutation, factory *testutil.FakeFactory, epoch int64, index []byte) ([]byte, error) {
	rtxn, err := factory.NewDBTxn(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create write transaction: %v", err)
	}
	mutation, err := m.Read(ctx, rtxn, epoch, index)
	if err != nil {
		return nil, fmt.Errorf("Read(%v, %v): %v, want nil", epoch, index, err)
	}
	if err := rtxn.Commit(); err != nil {
		return nil, fmt.Errorf("rtxn.Commit() failed: %v", err)
	}
	return mutation, nil
}

func TestRead(t *testing.T) {
	ctx := context.Background()
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db, mapID)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(t, ctx, m, factory)

	for _, tc := range []struct {
		description string
		epoch       int64
		index       []byte
		rMutation   []byte
	}{
		{"read a single mutation", 1, []byte("index1"), []byte("mutation1")},
		{"non-existing epoch", 100, []byte("index1"), nil},
		{"non-existing index", 1, []byte("index100"), nil},
	} {
		mutation, err := read(ctx, m, factory, tc.epoch, tc.index)
		if err != nil {
			t.Errorf("%v: failed to read mutations: %v", tc.description, err)
		}
		if got, want := mutation, tc.rMutation; !reflect.DeepEqual(got, want) {
			t.Errorf("%v: mutation=%v, want %v", tc.description, got, want)
		}
	}
}

func TestOverwriteMutation(t *testing.T) {
	ctx := context.Background()
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)
	m, err := New(db, mapID)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}
	fillDB(t, ctx, m, factory)

	for _, tc := range []struct {
		description string
		epoch       int64
		index       []byte
		wMutation   []byte
		rMutation   []byte
	}{
		{"overwrite epoch 2 mutation", 2, []byte("index2"), []byte("mutation3"), []byte("mutation3")},
		{"overwrite epoch 2 mutation again", 2, []byte("index2"), []byte("mutation4"), []byte("mutation4")},
	} {
		if err := write(ctx, m, factory, tc.epoch, tc.index, tc.wMutation); err != nil {
			t.Errorf("%v: failed to write mutation: %v", tc.description, err)
		}

		mutation, err := read(ctx, m, factory, tc.epoch, tc.index)
		if err != nil {
			t.Errorf("%v: failed to read mutations: %v", tc.description, err)
		}
		if got, want := mutation, tc.rMutation; !reflect.DeepEqual(got, want) {
			t.Errorf("%v: mutation=%v, want %v", tc.description, got, want)
		}
	}
}
