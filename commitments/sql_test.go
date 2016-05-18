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

package commitments

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func newDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func TestWriteRead(t *testing.T) {
	db := newDB(t)
	defer db.Close()

	key, commitment, _ := Commit([]byte("C"))
	c := New(db, "test")
	tests := []struct {
		commitment string
		key        string
		value      string
		want       bool
	}{
		{"A", "key 1", "value1", true},
		{"A", "key 1", "value1", true},
		{"A", "key 1", "value2", false},
		{"A", "key 2", "value2", false},
		{"B", "key 2", "value2", true},
		{string(commitment), string(key), "C", true},
	}
	for _, tc := range tests {
		err := c.WriteCommitment(nil, []byte(tc.commitment), []byte(tc.key), []byte(tc.value))
		if got := err == nil; got != tc.want {
			t.Fatalf("WriteCommitment(%v, %v, %v): %v, want %v", tc.commitment, tc.key, tc.value, err, tc.want)
		}
		if tc.want {
			value, err := c.ReadCommitment(nil, []byte(tc.commitment))
			if err != nil {
				t.Errorf("ReadCommitment(%v): %v", err)
			}
			if got := string(value.Data); got != tc.value {
				t.Errorf("ReadCommitment(%v): %v want %v", tc.commitment, got, tc.value)
			}
			if got := string(value.Key); got != tc.key {
				t.Errorf("ReadCommitment(%v): %v want %v", tc.commitment, got, tc.key)
			}
		}
	}
}
