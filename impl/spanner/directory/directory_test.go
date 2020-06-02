// Copyright 2020 Google Inc. All Rights Reserved.
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
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/google/go-cmp/cmp"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/keytransparency/impl/spanner/testutil"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ktspanner "github.com/google/keytransparency/impl/spanner"
	tpb "github.com/google/trillian"
)

// Verify that Table implements the directory.Storage interface.
var _ directory.Storage = &Table{}

func NewForTest(ctx context.Context, t *testing.T) directory.Storage {
	t.Helper()
	ddl, err := ktspanner.ReadDDL()
	if err != nil {
		t.Fatalf("ReadDDL: %v", err)
	}
	client := testutil.CreateDatabase(ctx, t, ddl)
	return New(client)
}

func TestList(t *testing.T) {
	ctx := context.Background()
	admin := NewForTest(ctx, t)

	directories := []*directory.Directory{
		{
			DirectoryID: "directory1",
			Map:         &tpb.Tree{TreeId: 1},
			Log:         &tpb.Tree{TreeId: 2},
			VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
			VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
			MinInterval: 1 * time.Second,
			MaxInterval: 5 * time.Second,
		},
		{
			DirectoryID: "directory2",
			Map:         &tpb.Tree{TreeId: 1},
			Log:         &tpb.Tree{TreeId: 2},
			VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
			VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
			MinInterval: 5 * time.Hour,
			MaxInterval: 500 * time.Hour,
			Deleted:     true,
		},
	}
	for _, d := range directories {
		if err := admin.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := admin.SetDelete(ctx, d.DirectoryID, d.Deleted); err != nil {
			t.Errorf("SetDelete(%v, %v): %v", d.DirectoryID, d.Deleted, err)
		}
	}

	for i, tc := range []struct {
		readDeleted bool
		want        []*directory.Directory
	}{
		{readDeleted: true, want: directories},
		{readDeleted: false, want: directories[:1]},
	} {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			directories, err := admin.List(ctx, tc.readDeleted)
			if err != nil {
				t.Fatalf("List(): %v", err)
			}
			if got, want := len(directories), len(tc.want); got != want {
				t.Fatalf("Got %v directories, want %v", got, want)
			}
			for i, d := range directories {
				if got, want := d, tc.want[i]; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
					t.Errorf("Directory[%v]: %v, want %v. Diff: %v", i, got, want, cmp.Diff(want, got, cmp.Comparer(proto.Equal)))
				}
			}
		})
	}
}

func TestWriteReadDelete(t *testing.T) {
	ctx := context.Background()
	admin := NewForTest(ctx, t)

	d := &directory.Directory{
		DirectoryID: "testdirectory",
		Map:         &tpb.Tree{TreeId: 1},
		Log:         &tpb.Tree{TreeId: 2},
		VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
		VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
		MinInterval: 1 * time.Second,
		MaxInterval: 5 * time.Second,
	}

	for _, tc := range []struct {
		desc         string
		write        bool
		wantWriteErr bool
		setDelete    bool
		isDeleted    bool
		readDeleted  bool
		wantReadCode codes.Code
	}{
		{desc: "NotFound", wantReadCode: codes.NotFound},
		{desc: "Success", write: true},
		{desc: "Duplicate DirectoryID", write: true, wantWriteErr: true},
		{desc: "Delete", setDelete: true, isDeleted: true, readDeleted: false, wantReadCode: codes.NotFound},
		{desc: "Read deleted", setDelete: true, isDeleted: true, readDeleted: true},
		{desc: "Undelete", setDelete: true, isDeleted: false, readDeleted: false},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			if tc.write {
				err := admin.Write(ctx, d)
				if got, want := err != nil, tc.wantWriteErr; got != want {
					t.Fatalf("Write(): %v, want err: %v", err, want)
				}
				if err != nil {
					return
				}
			}
			if tc.setDelete {
				if err := admin.SetDelete(ctx, d.DirectoryID, tc.isDeleted); err != nil {
					t.Fatalf("SetDelete(%v, %v): %v", d.DirectoryID, tc.isDeleted, err)
				}
			}

			directory, err := admin.Read(ctx, d.DirectoryID, tc.readDeleted)
			if got, want := status.Code(err), tc.wantReadCode; got != want {
				t.Errorf("Read(): %v, want code: %v", err, want)
			}
			if err != nil {
				return
			}
			d.Deleted = tc.isDeleted
			if got, want := *directory, *d; !cmp.Equal(got, want, cmp.Comparer(proto.Equal)) {
				t.Errorf("Directory: %v, want %v. Diff:%v", got, want, cmp.Diff(want, got))
			}
		})
	}
}

func TestDelete(t *testing.T) {
	ctx := context.Background()
	s := NewForTest(ctx, t)

	for _, dirID := range []string{"test", ""} {
		d := &directory.Directory{
			DirectoryID: dirID,
			Map:         &tpb.Tree{TreeId: 1},
			Log:         &tpb.Tree{TreeId: 2},
			VRF:         &keyspb.PublicKey{Der: []byte("pubkeybytes")},
			VRFPriv:     &keyspb.PrivateKey{Der: []byte("privkeybytes")},
			MinInterval: 1 * time.Second,
			MaxInterval: 5 * time.Second,
		}
		if err := s.Write(ctx, d); err != nil {
			t.Errorf("Write(): %v", err)
		}
		if err := s.Delete(ctx, dirID); err != nil {
			t.Errorf("Delete(): %v", err)
		}
		_, err := s.Read(ctx, dirID, true)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
		_, err = s.Read(ctx, dirID, false)
		if got, want := status.Code(err), codes.NotFound; got != want {
			t.Errorf("Read(): %v, wanted %v", got, want)
		}
	}
}
