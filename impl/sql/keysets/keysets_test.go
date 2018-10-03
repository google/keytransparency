// Copyright 2018 Google Inc. All Rights Reserved.
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
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/tink"

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

	if err := signature.Register(); err != nil {
		t.Fatalf("Register(): %v", err)
	}
	ks, err := tink.NewKeysetHandle(signature.ECDSAP256KeyTemplate())
	if err != nil {
		t.Fatalf("tink.GenerateNew(): %v", err)
	}
	for _, tc := range []struct {
		desc         string
		instanceID   int64
		domainID     string
		appID        string
		write        bool
		wantWriteErr bool
		read         bool
		wantReadErr  bool
	}{
		{
			desc:       "write,read",
			instanceID: 0,
			domainID:   "domain",
			appID:      "app",
			write:      true,
			read:       true,
		},
		{
			desc:         "double write",
			instanceID:   0,
			domainID:     "domain",
			appID:        "app",
			write:        true,
			wantWriteErr: true,
		},
		{
			desc:        "notfound",
			instanceID:  1,
			domainID:    "domain",
			appID:       "app",
			read:        true,
			wantReadErr: true,
		},
	} {
		if tc.write {
			err := keysets.Set(ctx, tc.instanceID, tc.domainID, tc.appID, ks)
			if got, want := err != nil, tc.wantWriteErr; got != want {
				t.Errorf("Set(%v): %v, wantErr %v", tc.instanceID, err, want)
			}
		}
		if tc.read {
			gotKs, err := keysets.Get(ctx, tc.instanceID, tc.domainID, tc.appID)
			if got, want := err != nil, tc.wantReadErr; got != want {
				t.Errorf("Read(%v): %v, wantErr %v", tc.instanceID, err, want)
			}
			if err != nil {
				continue
			}
			if got, want := gotKs.Keyset(), ks.Keyset(); !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Read(%v): %v, want %v", tc.instanceID, got, want)
			}
		}
	}
}
