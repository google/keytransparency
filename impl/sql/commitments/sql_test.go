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

	"github.com/google/keytransparency/core/commitments"

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
	p := &tpb.Profile{Keys: map[string][]byte{"foo": []byte("cat")}}
	a, err := proto.Marshal(p)
	if err != nil {
		t.Fatalf("Failed to marshal profile: %v", err)
	}
	commitmentC, committedC, err := commitments.Commit("foo", a)
	if err != nil {
		t.Fatalf("Failed to create commitment: %v", err)
	}

	for _, tc := range []struct {
		commitment, key []byte
		value           *tpb.Profile
		wantNoErr       bool
	}{
		{[]byte("committmentA"), []byte("key 1"), &tpb.Profile{}, true},
		{[]byte("committmentA"), []byte("key 1"), &tpb.Profile{}, true},
		{[]byte("committmentA"), []byte("key 1"), &tpb.Profile{Keys: map[string][]byte{"foo": []byte("bar")}}, false},
		{[]byte("committmentA"), []byte("key 2"), &tpb.Profile{Keys: map[string][]byte{"foo": []byte("bar")}}, false},
		{[]byte("committmentB"), []byte("key 2"), &tpb.Profile{Keys: map[string][]byte{"foo": []byte("bar")}}, true},
		{commitmentC, committedC.Key, p, true},
	} {
		a, err := proto.Marshal(tc.value)
		if err != nil {
			t.Errorf("Failed to marshal profile: %v", err)
		}
		committed := &tpb.Committed{Key: tc.key, Data: a}
		err = c.Write(nil, tc.commitment, committed)
		if got := err == nil; got != tc.wantNoErr {
			t.Errorf("WriteCommitment(%s, %v): %v, want %v", tc.commitment, committed, err, tc.wantNoErr)
		}
		if tc.wantNoErr {
			value, err := c.Read(nil, tc.commitment)
			if err != nil {
				t.Errorf("Read(_, %v): %v", tc.commitment, err)
			}
			if !proto.Equal(value, committed) {
				t.Errorf("Read(%v): %v want %v", tc.commitment, value, committed)
			}
		}
	}
}
