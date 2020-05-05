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

// Package directory reads and writes Key Transparency Directory information.
package directory

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	ktspanner "github.com/google/keytransparency/impl/spanner"
	tpb "github.com/google/trillian"
)

const table = "Directories"

var directoriesCols = []string{"DirectoryID", "Map", "Log", "VRFPublicKey", "VRFPrivateKey", "MinInterval", "MaxInterval", "Deleted"}

var _ directory.Storage = &Table{}

// Table gives access to the directory table.
type Table struct {
	db *ktspanner.Database
}

// New returns a directory.Storage client backed by Spanner.
func New(db *ktspanner.Database) *Table {
	return &Table{db: db}
}

// spannerDirectory represents one row in the Directories table in spanner.
type spannerDirectory struct {
	DirectoryID   string
	Map           []byte
	Log           []byte
	VRFPublicKey  []byte
	VRFPrivateKey []byte
	MinInterval   int64
	MaxInterval   int64
	Deleted       bool
}

func readRow(row *spanner.Row) (*directory.Directory, error) {
	var r spannerDirectory
	if err := row.ToStruct(&r); err != nil {
		return nil, err
	}

	vrfPriv, err := unwrapAnyProto(r.VRFPrivateKey)
	if err != nil {
		return nil, err
	}

	var tmap tpb.Tree
	if err := proto.Unmarshal(r.Map, &tmap); err != nil {
		return nil, err
	}
	var tlog tpb.Tree
	if err := proto.Unmarshal(r.Log, &tlog); err != nil {
		return nil, err
	}

	return &directory.Directory{
		DirectoryID: r.DirectoryID,
		Map:         &tmap,
		Log:         &tlog,
		VRF:         &keyspb.PublicKey{Der: r.VRFPublicKey},
		VRFPriv:     vrfPriv,
		MinInterval: time.Duration(r.MinInterval) * time.Nanosecond,
		MaxInterval: time.Duration(r.MaxInterval) * time.Nanosecond,
		Deleted:     r.Deleted,
	}, nil
}

// List returns all Directories. showDeleted indicates whether deleted directories should be returned.
func (t *Table) List(ctx context.Context, showDeleted bool) ([]*directory.Directory, error) {
	client, err := t.db.Get(ctx)
	if err != nil {
		return nil, err
	}
	rtx := client.Single()
	defer rtx.Close()

	ret := []*directory.Directory{}
	err = rtx.Read(ctx, table, spanner.AllKeys(), directoriesCols).Do(
		func(r *spanner.Row) error {
			d, err := readRow(r)
			if err != nil {
				return err
			}
			if d.Deleted && !showDeleted {
				return nil
			}
			ret = append(ret, d)
			return nil
		})
	return ret, err
}

// Write creates a new Directory.
func (t *Table) Write(ctx context.Context, dir *directory.Directory) error {
	client, err := t.db.Get(ctx)
	if err != nil {
		return err
	}
	// Prepare data.
	anyPB, err := ptypes.MarshalAny(dir.VRFPriv)
	if err != nil {
		return err
	}
	anyData, err := proto.Marshal(anyPB)
	if err != nil {
		return err
	}

	tmap, err := proto.Marshal(dir.Map)
	if err != nil {
		return err
	}
	tlog, err := proto.Marshal(dir.Log)
	if err != nil {
		return err
	}

	m, err := spanner.InsertStruct(table, spannerDirectory{
		DirectoryID:   dir.DirectoryID,
		Map:           tmap,
		Log:           tlog,
		VRFPublicKey:  dir.VRF.GetDer(),
		VRFPrivateKey: anyData,
		MinInterval:   dir.MinInterval.Nanoseconds(),
		MaxInterval:   dir.MaxInterval.Nanoseconds(),
		Deleted:       false,
	})
	if err != nil {
		return err
	}

	_, err = client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Read retriaves a directory from storage. Returns status.NotFound if the row is deleted.
func (t *Table) Read(ctx context.Context, directoryID string, showDeleted bool) (*directory.Directory, error) {
	client, err := t.db.Get(ctx)
	if err != nil {
		return nil, err
	}
	rtx := client.Single()
	defer rtx.Close()
	row, err := rtx.ReadRow(ctx, table, spanner.Key{directoryID}, directoriesCols)
	if err != nil {
		return nil, err
	}
	dir, err := readRow(row)
	if err != nil {
		return nil, err
	}
	if !showDeleted && dir.Deleted {
		return nil, status.Errorf(codes.NotFound, "Directory %v is deleted", directoryID)
	}
	return dir, nil
}

// unwrapAnyProto returns the proto object seralized inside a serialized any.Any
func unwrapAnyProto(anyData []byte) (proto.Message, error) {
	var anyPB any.Any
	if err := proto.Unmarshal(anyData, &anyPB); err != nil {
		return nil, err
	}
	var privKey ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(&anyPB, &privKey); err != nil {
		return nil, err
	}
	return privKey.Message, nil
}

// SetDelete deletes or undeletes a directory.
func (t *Table) SetDelete(ctx context.Context, directoryID string, isDeleted bool) error {
	client, err := t.db.Get(ctx)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{
		spanner.Update(table, []string{"DirectoryID", "Deleted", "DeleteTime"},
			[]interface{}{directoryID, isDeleted, time.Now()}),
	})
	return err
}

// Delete permanently deletes a directory.
func (t *Table) Delete(ctx context.Context, directoryID string) error {
	client, err := t.db.Get(ctx)
	if err != nil {
		return err
	}
	_, err = client.Apply(ctx, []*spanner.Mutation{
		spanner.Delete(table, spanner.Key{directoryID}),
	})
	return err
}
