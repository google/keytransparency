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

package sequenced

import (
	"bytes"
	"context"
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"

	"github.com/google/keytransparency/impl/sql/testutil"
)

func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func TestGetLatest(t *testing.T) {
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)

	a, err := New(db, 0)
	if err != nil {
		t.Fatalf("Failed to create sequenced: %v", err)
	}

	for _, tc := range []struct {
		mapID int64
		epoch int64
		data  []byte
		want  int64
	}{
		{0, 0, []byte("foo"), 0},
		{0, 10, []byte("foo"), 10},
		{0, 5, []byte("foo"), 10},
	} {
		txn, err := factory.NewDBTxn(context.Background())
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		if err = a.Write(txn, tc.mapID, tc.epoch, tc.data); err != nil {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}
		if err = txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}

		var obj []byte
		txn2, err := factory.NewDBTxn(context.Background())
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		epoch, err := a.Latest(txn2, tc.mapID, &obj)
		if err != nil {
			t.Errorf("Latest(): %v, want nil", err)
		}
		if err = txn2.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}
		if got, want := epoch, tc.want; got != want {
			t.Errorf("Latest(): %v, want %v", got, want)
		}
	}
}

func TestWriteRead(t *testing.T) {
	db := NewDB(t)
	factory := testutil.NewFakeFactory(db)

	a, err := New(db, 0)
	if err != nil {
		t.Fatalf("Failed to create appender: %v", err)
	}

	for _, tc := range []struct {
		mapID int64
		epoch int64
		data  []byte
		want  bool
	}{
		{0, 0, []byte("foo"), true},
		{0, 0, []byte("foo"), false},
		{0, 1, []byte("foo"), true},
	} {
		txn, err := factory.NewDBTxn(context.Background())
		if err != nil {
			t.Errorf("factory.NewDBTxn() failed: %v", err)
			continue
		}
		err = a.Write(txn, tc.mapID, tc.epoch, tc.data)
		if got, want := err == nil, tc.want; got != want {
			t.Errorf("Append(%v, %v): %v, want nil? %v", tc.epoch, tc.data, err, want)
		}
		if err := txn.Commit(); err != nil {
			t.Errorf("txn.Commit() failed: %v", err)
		}

		if tc.want {
			txn2, err := factory.NewDBTxn(context.Background())
			if err != nil {
				t.Errorf("factory.NewDBTxn() failed: %v", err)
				continue
			}
			var readData []byte
			err = a.Read(txn2, tc.mapID, tc.epoch, &readData)
			if err != nil {
				t.Errorf("Read(%v, %v): %v, want nil", tc.epoch, tc.data, err)
			}
			if err := txn2.Commit(); err != nil {
				t.Errorf("txn2.Commit() failed: %v", err)
			}
			if got, want := readData, tc.data; !bytes.Equal(got, want) {
				t.Errorf("Read(%v, %v): %x, want %x", tc.mapID, tc.epoch, got, want)
			}
		}
	}
}
