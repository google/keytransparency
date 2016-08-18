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

	"github.com/google/key-transparency/core/commitments"

	_ "github.com/mattn/go-sqlite3"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

func TestWriteRead(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()

	commitmentC, committedC, _ := commitments.Commit("foo", []byte("C"))
	c, err := New(db, "test")
	if err != nil {
		t.Fatalf("Failed to create committer: %v", err)
	}

	for _, tc := range []struct {
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
		{string(commitmentC), string(committedC.Data), "C", true},
	} {
		committed := &tpb.Committed{Key: []byte(tc.key), Data: []byte(tc.value)}
		err := c.Write(nil, []byte(tc.commitment), committed)
		if got := err == nil; got != tc.want {
			t.Fatalf("WriteCommitment(%v, %v, %v): %v, want %v", tc.commitment, tc.key, tc.value, err, tc.want)
		}
		if tc.want {
			value, err := c.Read(nil, []byte(tc.commitment))
			if err != nil {
				t.Errorf("Read(_, %v): %v", []byte(tc.commitment), err)
			}
			if got := string(value.Data); got != tc.value {
				t.Errorf("Read(%v): %v want %v", tc.commitment, got, tc.value)
			}
			if got := string(value.Key); got != tc.key {
				t.Errorf("Read(%v): %v want %v", tc.commitment, got, tc.key)
			}
		}
	}
}
