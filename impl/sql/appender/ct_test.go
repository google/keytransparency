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

package appender

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/key-transparency/core/testutil/ctutil"
	"github.com/google/key-transparency/impl/sql/testutil"

	ct "github.com/google/certificate-transparency/go"
	"github.com/google/certificate-transparency/go/tls"
	_ "github.com/mattn/go-sqlite3"
)

const (
	mapID = "test"
)

func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func TestGetLatest(t *testing.T) {
	ctx := context.Background()
	hs := ctutil.NewCTServer(t)
	defer hs.Close()
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)

	a, err := New(ctx, db, mapID, hs.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create appender: %v", err)
	}

	for _, tc := range []struct {
		epoch int64
		data  []byte
		want  int64
	}{
		{0, []byte("foo"), 0},
		{10, []byte("foo"), 10},
		{5, []byte("foo"), 10},
	} {
		txn, err := factory.NewDBTxn(context.Background())
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		if err := a.Append(ctx, txn, tc.epoch, tc.data); err != nil {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}

		var obj []byte
		epoch, b, err := a.Latest(context.Background(), &obj)
		if err != nil {
			t.Errorf("Latest(): %v, want nil", err)
		}
		if got := epoch; got != tc.want {
			t.Errorf("Latest(): %v, want %v", got, tc.want)
		}
		sct := new(ct.SignedCertificateTimestamp)
		if _, err := tls.Unmarshal(b, sct); err != nil {
			t.Errorf("Failed to deserialize SCT: %v", err)
		}
	}
}

func TestAppend(t *testing.T) {
	ctx := context.Background()
	hs := ctutil.NewCTServer(t)
	defer hs.Close()
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)

	a, err := New(ctx, db, mapID, hs.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create appender: %v", err)
	}

	for _, tc := range []struct {
		epoch int64
		data  []byte
		want  bool
	}{
		{0, []byte("foo"), true},
		{0, []byte("foo"), false},
		{1, []byte("foo"), true},
	} {
		txn, err := factory.NewDBTxn(context.Background())
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		err = a.Append(ctx, txn, tc.epoch, tc.data)
		if got := err == nil; got != tc.want {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}
	}
}
