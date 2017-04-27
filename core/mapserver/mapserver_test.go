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

package mapserver

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/keytransparency/impl/sql/sequenced"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/sql/testutil"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/util"

	_ "github.com/mattn/go-sqlite3"
)

type env struct {
	mapID int64
	db    *sql.DB
	m     trillian.TrillianMapClient
	ro    trillian.TrillianMapClient
}

func newEnv() (*env, error) {
	mapID := int64(0)
	sqldb, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("sql.Open(): %v", err)
	}
	factory := testutil.NewFakeFactory(sqldb)
	tree, err := sqlhist.New(context.Background(), mapID, factory)
	if err != nil {
		return nil, err
	}
	sths, err := sequenced.New(sqldb, mapID)
	if err != nil {
		return nil, err
	}
	signer, err := keys.NewFromPrivatePEM(`-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHgSC8WzQK0bxSmfJWUeMP5GdndqUw8zS1dCHQ+3otj/oAoGCCqGSM49
AwEHoUQDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhWf5JqSoyp0uiL8LeNYyj5vgkl
K8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END EC PRIVATE KEY-----`, "")
	if err != nil {
		return nil, err
	}
	clock := util.NewFakeTimeSource(time.Now())
	m := New(mapID, tree, factory, sths, signer, clock)
	ro := NewReadonly(mapID, tree, factory, sths)

	return &env{
		mapID: mapID,
		db:    sqldb,
		m:     m,
		ro:    ro,
	}, nil
}

func index(i int) []byte {
	idx := make([]byte, 32)
	idx[0] = byte(i)
	return idx
}

func TestSetGet(t *testing.T) {
	ctx := context.Background()
	env, err := newEnv()
	if err != nil {
		t.Fatalf("Error creating env: %v", err)
	}
	defer env.db.Close()

	for i, tc := range []struct {
		epoch  int64
		leaves []*trillian.MapLeaf
	}{
		{
			epoch: 0,
			leaves: []*trillian.MapLeaf{
				{Index: index(0), LeafValue: []byte("foo")},
				{Index: index(1), LeafValue: []byte("bar")},
			}},
		{
			epoch: 1,
			leaves: []*trillian.MapLeaf{
				{Index: index(0), LeafValue: []byte("foo1")},
				{Index: index(1), LeafValue: []byte("bar1")},
			}},
	} {
		resp, err := env.m.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
			MapId:  env.mapID,
			Leaves: tc.leaves,
		})
		if err != nil {
			t.Errorf("SetLeaves(%v): %v", i, err)
			continue
		}
		if got, want := resp.MapRoot.MapRevision, tc.epoch; got != want {
			t.Errorf("SetLeaves(%v).MapRevision: %v, want %v", i, got, want)
		}

		indexes := make([][]byte, 0, len(tc.leaves))
		for _, l := range tc.leaves {
			indexes = append(indexes, l.Index)
		}
		resp2, err := env.ro.GetLeaves(ctx, &trillian.GetMapLeavesRequest{
			MapId:    env.mapID,
			Revision: tc.epoch,
			Index:    indexes,
		})
		if err != nil {
			t.Errorf("GetLeaves(%v): %v", i, err)
			continue
		}
		if got, want := resp2.MapRoot.MapRevision, tc.epoch; got != want {
			t.Errorf("GetLeaves(%v).MapRevision: %v, want %v", i, got, want)
			continue
		}
		for k, l := range resp2.MapLeafInclusion {
			if got, want := l.Leaf.Index, tc.leaves[k].Index; !bytes.Equal(got, want) {
				t.Errorf("GetLeaves(%v).Index[%v]: %s, want %s", i, k, got, want)
			}
			if got, want := l.Leaf.LeafValue, tc.leaves[k].LeafValue; !bytes.Equal(got, want) {
				t.Errorf("GetLeaves(%v).LeafValue[%v]: %s, want %s", i, k, got, want)
			}
		}
	}
}

func TestGetSignedMapRoot(t *testing.T) {
	ctx := context.Background()
	env, err := newEnv()
	if err != nil {
		t.Fatalf("Error creating env: %v", err)
	}
	defer env.db.Close()

	for i, tc := range []struct {
		epoch  int64
		leaves []*trillian.MapLeaf
	}{
		{
			epoch: 0,
			leaves: []*trillian.MapLeaf{
				{Index: index(0), LeafValue: []byte("foo")},
				{Index: index(1), LeafValue: []byte("bar")},
			}},
		{
			epoch: 1,
			leaves: []*trillian.MapLeaf{
				{Index: index(0), LeafValue: []byte("foo1")},
				{Index: index(1), LeafValue: []byte("bar1")},
			}},
	} {
		resp, err := env.m.SetLeaves(ctx, &trillian.SetMapLeavesRequest{
			MapId:  env.mapID,
			Leaves: tc.leaves,
		})
		if err != nil {
			t.Errorf("SetLeaves(%v): %v", i, err)
			continue
		}
		if got, want := resp.MapRoot.MapRevision, tc.epoch; got != want {
			t.Errorf("SetLeaves(%v).MapRevision: %v, want %v", i, got, want)
		}

		rootResp, err := env.ro.GetSignedMapRoot(ctx, &trillian.GetSignedMapRootRequest{
			MapId: env.mapID,
		})
		if err != nil {
			t.Errorf("SetLeaves(%v): %v", i, err)
			continue
		}
		if got, want := rootResp.GetMapRoot().MapRevision, tc.epoch; got != want {
			t.Errorf("GetMapRoot().MapRevision: %v, want %v", i, err)
		}
	}
}
