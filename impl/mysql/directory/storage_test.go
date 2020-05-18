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

package directory

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/impl/mysql/testdb"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/trillian"
)

func newStorage(ctx context.Context, t *testing.T) directory.Storage {
	t.Helper()
	db := testdb.NewForTest(ctx, t)
	s, err := NewStorage(db)
	if err != nil {
		t.Fatalf("Failed to create adminstorage: %v", err)
	}
	return s
}

func TestList(t *testing.T) {
	ctx := context.Background()
	s := newStorage(ctx, t)
	for _, tc := range []struct {
		directories []*directory.Directory
		readDeleted bool
	}{
		{
			directories: []*directory.Directory{
				{
					DirectoryID: "directory1",
					Map: &tpb.Tree{
						TreeId: 1,
					},
					Log: &tpb.Tree{
						TreeId: 2,
					},
					VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
					VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
					MinInterval: 1 * time.Second,
					MaxInterval: 5 * time.Second,
				},
				{
					DirectoryID: "directory2",
					Map: &tpb.Tree{
						TreeId: 1,
					},
					Log: &tpb.Tree{
						TreeId: 2,
					},
					VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
					VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
					MinInterval: 5 * time.Hour,
					MaxInterval: 500 * time.Hour,
				},
			},
		},
	} {
		for _, d := range tc.directories {
			if err := s.Write(ctx, d); err != nil {
				t.Errorf("Write(): %v", err)
				continue
			}
		}

		directories, err := s.List(ctx, tc.readDeleted)
		if err != nil {
			t.Errorf("List(): %v", err)
			continue
		}
		if got, want := directories, tc.directories; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
			t.Errorf("List(): %#v, want %#v, diff: \n%v", got, want, cmp.Diff(got, want))
		}
	}
}

func TestWriteReadDelete(t *testing.T) {
	ctx := context.Background()
	s := newStorage(ctx, t)
	for _, tc := range []struct {
		desc                 string
		d                    directory.Directory
		write                bool
		wantWriteErr         bool
		setDelete, isDeleted bool
		readDeleted          bool
		wantReadErr          bool
	}{
		{
			desc:  "Success",
			write: true,
			d: directory.Directory{
				DirectoryID: "testdirectory",
				Map: &tpb.Tree{
					TreeId: 1,
				},
				Log: &tpb.Tree{
					TreeId: 2,
				},
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
		},
		{
			desc:  "Duplicate DirectoryID",
			write: true,
			d: directory.Directory{
				DirectoryID: "testdirectory",
				Map: &tpb.Tree{
					TreeId: 1,
				},
				Log: &tpb.Tree{
					TreeId: 2,
				},
				VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
				VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
				MinInterval: 1 * time.Second,
				MaxInterval: 5 * time.Second,
			},
			wantWriteErr: true,
		},
		{
			desc: "Delete",
			d: directory.Directory{
				DirectoryID: "testdirectory",
				Map: &tpb.Tree{
					TreeId: 1,
				},
				Log: &tpb.Tree{
					TreeId: 2,
				},
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
			d: directory.Directory{
				DirectoryID: "testdirectory",
				Map: &tpb.Tree{
					TreeId: 1,
				},
				Log: &tpb.Tree{
					TreeId: 2,
				},
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
			d: directory.Directory{
				DirectoryID: "testdirectory",
				Map: &tpb.Tree{
					TreeId: 1,
				},
				Log: &tpb.Tree{
					TreeId: 2,
				},
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
				err := s.Write(ctx, &tc.d)
				if got, want := err != nil, tc.wantWriteErr; got != want {
					t.Errorf("Write(): %v, want err: %v", err, want)
					return
				}
				if err != nil {
					return
				}
			}
			if tc.setDelete {
				tc.d.DeletedTimestamp = time.Now().Truncate(time.Second)
				tc.d.Deleted = tc.isDeleted
				if err := s.SetDelete(ctx, tc.d.DirectoryID, tc.isDeleted); err != nil {
					t.Errorf("SetDelete(%v, %v): %v", tc.d.DirectoryID, tc.isDeleted, err)
					return
				}
			}

			directory, err := s.Read(ctx, tc.d.DirectoryID, tc.readDeleted)
			if got, want := err != nil, tc.wantReadErr; got != want {
				t.Errorf("Read(): %v, want err: %v", err, want)
			}
			if err != nil {
				return
			}
			if got, want := *directory, tc.d; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Read(%v, %v): %#v, want %#v, diff: \n%v",
					tc.d.DirectoryID, tc.readDeleted, got, want, cmp.Diff(got, want))
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s := newStorage(ctx, t)
	for _, tc := range []struct {
		directoryID string
	}{
		{directoryID: "test"},
	} {
		d := &directory.Directory{
			Map: &tpb.Tree{
				TreeId: 1,
			},
			Log: &tpb.Tree{
				TreeId: 2,
			},
			DirectoryID: tc.directoryID,
			VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
			VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
		}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.Delete(ctx, tc.directoryID); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, tc.directoryID, true)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
		_, err = s.Read(ctx, tc.directoryID, false)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
	}
}
