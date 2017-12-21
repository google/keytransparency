// Copyright 2017 Google Inc. All Rights Reserved.
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

package keysets

import (
	"context"
	"database/sql"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
	_ "github.com/mattn/go-sqlite3"
)

func TestWriteRead(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	keysets, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create keysets.Storage")
	}

	for _, tc := range []struct {
		instanceID int64
		domainID   string
		appID      string
		ks         *tpb.KeySet
		write      bool
		writeErr   bool
		read       bool
		readErr    bool
	}{
		{
			instanceID: 0,
			domainID:   "domain",
			appID:      "app",
			ks: &tpb.KeySet{VerifyingKeys: map[string]*tpb.VerifyingKey{
				"1": {KeyMaterial: []byte("keydata")},
			}},
			write: true,
			read:  true,
		},
	} {
		if tc.write {
			err := keysets.Set(ctx, tc.instanceID, tc.domainID, tc.appID, tc.ks)
			if got, want := err != nil, tc.writeErr; got != want {
				t.Errorf("Set(%v): %v, wantErr %v", tc.instanceID, err, want)
			}
		}
		if tc.read {
			ks, err := keysets.Get(ctx, tc.instanceID, tc.domainID, tc.appID)
			if got, want := err != nil, tc.readErr; got != want {
				t.Errorf("Read(%v): %v, wantErr %v", tc.instanceID, err, want)
			}
			if got, want := ks, tc.ks; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Read(%v): %v, want %v", tc.instanceID, got, want)
			}
		}
	}
}
