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

package domain

import (
	"context"
	"database/sql"
	"reflect"
	"testing"
	"time"

	"github.com/google/keytransparency/core/domain"

	"github.com/google/trillian/crypto/keyspb"

	_ "github.com/mattn/go-sqlite3"
)

func TestList(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	admin, err := NewStorage(db)
	if err != nil {
		t.Fatalf("Failed to create adminstorage: %v", err)
	}
	for _, tc := range []struct {
		domains     []*domain.Domain
		readDeleted bool
	}{
		{
			domains: []*domain.Domain{
				{
					DomainID:    "domain1",
					MapID:       1,
					LogID:       2,
					VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
					VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
					MinInterval: 1 * time.Second,
					MaxInterval: 5 * time.Second,
				},
				{
					DomainID:    "domain2",
					MapID:       1,
					LogID:       2,
					VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
					VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
					MinInterval: 5 * time.Hour,
					MaxInterval: 500 * time.Hour,
				},
			},
		},
	} {
		for _, d := range tc.domains {
			if err := admin.Write(ctx, d); err != nil {
				t.Errorf("Write(): %v", err)
				continue
			}
		}

		domains, err := admin.List(ctx, tc.readDeleted)
		if err != nil {
			t.Errorf("List(): %v", err)
			continue
		}
		if got, want := domains, tc.domains; !reflect.DeepEqual(got, want) {
			t.Errorf("Domain: %v, want %v", got, want)
		}
	}
}

func TestWriteReadDelete(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	defer db.Close()
	admin, err := NewStorage(db)
	if err != nil {
		t.Fatalf("Failed to create adminstorage: %v", err)
	}

	for _, tc := range []struct {
		desc                 string
		d                    domain.Domain
		write                bool
		wantWriteErr         bool
		setDelete, isDeleted bool
		readDeleted          bool
		wantReadErr          bool
	}{
		{
			desc:  "Success",
			write: true,
			d: domain.Domain{
				DomainID:    "testdomain",
				MapID:       1,
				LogID:       2,
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
		},
		{
			desc:  "Duplicate DomainID",
			write: true,
			d: domain.Domain{
				DomainID:    "testdomain",
				MapID:       1,
				LogID:       2,
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
			wantWriteErr: true,
		},
		{
			desc: "Delete",
			d: domain.Domain{
				DomainID:    "testdomain",
				MapID:       1,
				LogID:       2,
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
			setDelete:   true,
			isDeleted:   true,
			readDeleted: false,
			wantReadErr: true,
		},
		{
			desc: "Read deleted",
			d: domain.Domain{
				DomainID:    "testdomain",
				MapID:       1,
				LogID:       2,
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
			setDelete:   true,
			isDeleted:   true,
			readDeleted: true,
			wantReadErr: false,
		},
		{
			desc: "Undelete",
			d: domain.Domain{
				DomainID:    "testdomain",
				MapID:       1,
				LogID:       2,
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
			setDelete:   true,
			isDeleted:   false,
			readDeleted: false,
			wantReadErr: false,
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.write {
				err := admin.Write(ctx, &tc.d)
				if got, want := err != nil, tc.wantWriteErr; got != want {
					t.Errorf("Write(): %v, want err: %v", err, want)
					return
				}
				if err != nil {
					return
				}
			}
			if tc.setDelete {
				if err := admin.SetDelete(ctx, tc.d.DomainID, tc.isDeleted); err != nil {
					t.Errorf("SetDelete(%v, %v): %v", tc.d.DomainID, tc.isDeleted, err)
					return
				}
			}

			domain, err := admin.Read(ctx, tc.d.DomainID, tc.readDeleted)
			if got, want := err != nil, tc.wantReadErr; got != want {
				t.Errorf("Read(): %v, want err: %v", err, want)
			}
			if err != nil {
				return
			}
			tc.d.Deleted = tc.isDeleted
			if got, want := *domain, tc.d; !reflect.DeepEqual(got, want) {
				t.Errorf("Domain: %v, want %v", got, want)
			}
		})
	}
}
