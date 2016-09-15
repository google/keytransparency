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
	"bytes"
	"database/sql"
	"testing"

	"github.com/google/key-transparency/core/testutil/ctutil"

	ct "github.com/google/certificate-transparency/go"
	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/net/context"
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
	hs := ctutil.NewCTServer(t)
	defer hs.Close()

	a, err := New(NewDB(t), mapID, hs.URL)
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
		if err := a.Append(context.Background(), tc.epoch, tc.data); err != nil {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}

		var obj []byte
		epoch, b, err := a.Latest(context.Background(), &obj)
		if err != nil {
			t.Errorf("Latest(): %v, want nil", err)
		}
		if got := epoch; got != tc.want {
			t.Errorf("Latest(): %v, want %v", got, tc.want)
		}
		_, err = ct.DeserializeSCT(bytes.NewReader(b))
		if err != nil {
			t.Errorf("Failed to deserialize SCT: %v", err)
		}
	}
}
func TestAppend(t *testing.T) {
	hs := ctutil.NewCTServer(t)
	defer hs.Close()

	a, err := New(NewDB(t), mapID, hs.URL)
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
		err := a.Append(context.Background(), tc.epoch, tc.data)
		if got := err == nil; got != tc.want {
			t.Errorf("Append(%v, %v): %v, want nil", tc.epoch, tc.data, err)
		}
	}
}
