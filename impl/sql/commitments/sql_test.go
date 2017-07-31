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

	"github.com/google/keytransparency/core/crypto/commitments"

	"github.com/golang/protobuf/proto"
	_ "github.com/mattn/go-sqlite3"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

func TestWriteRead(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	c, err := New(db, 1)
	if err != nil {
		t.Fatalf("Failed to create committer: %v", err)
	}

	// Create test data.
	pdata := []byte("key")
	commitment, nonce, err := commitments.Commit("foo", "app", pdata)
	if err != nil {
		t.Fatalf("Failed to create commitment: %v", err)
	}

	for _, tc := range []struct {
		commitment, key []byte
		value           []byte
		wantNoErr       bool
	}{
		{[]byte("committmentA"), []byte("key 1"), []byte{}, true},
		{[]byte("committmentA"), []byte("key 1"), []byte{}, true},
		{[]byte("committmentA"), []byte("key 1"), []byte("key1"), false},
		{[]byte("committmentA"), []byte("key 2"), []byte("key2"), false},
		{[]byte("committmentB"), []byte("key 2"), []byte("key2"), true},
		{commitment, nonce, pdata, true},
	} {
		committed := &tpb.Committed{Key: tc.key, Data: tc.value}
		err = c.Write(nil, tc.commitment, tc.value, tc.key)
		if got := err == nil; got != tc.wantNoErr {
			t.Errorf("WriteCommitment(%s, %v): %v, want %v", tc.commitment, committed, err, tc.wantNoErr)
		}
		if tc.wantNoErr {
			data, nonce, err := c.Read(nil, tc.commitment)
			if err != nil {
				t.Errorf("Read(_, %v): %v", tc.commitment, err)
			}
			if got, want := (&tpb.Committed{Key: nonce, Data: data}), committed; !proto.Equal(got, want) {
				t.Errorf("Read(%v): %v want %v", tc.commitment, got, want)
			}
		}
	}
}
