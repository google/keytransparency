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
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/google/keytransparency/core/directory"
	"github.com/google/trillian/crypto/keyspb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	tpb "github.com/google/trillian"
)

const table = "Directories"

// dirRow represents one row in the Directories table in Spanner.
type dirRow struct {
	DirectoryID   string
	Map           []byte
	Log           []byte
	VRFPublicKey  []byte
	VRFPrivateKey []byte
	MinInterval   int64
	MaxInterval   int64
	Deleted       bool
	DeleteTime    time.Time
}

var dirColumns = []string{
	"DirectoryID",
	"Map",
	"Log",
	"VRFPublicKey",
	"VRFPrivateKey",
	"MinInterval",
	"MaxInterval",
	"Deleted",
	"DeleteTime",
}

// Table gives access to the directory table.
type Table struct {
	client *spanner.Client
}

// New returns a directory.Storage client backed by Spanner.
func New(client *spanner.Client) *Table {
	return &Table{client: client}
}

func unpackRow(row *spanner.Row) (*directory.Directory, error) {
	var r dirRow
	if err := row.ToStruct(&r); err != nil {
		return nil, err
	}

	vrfPriv, err := unmarshalAny(r.VRFPrivateKey)
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

// List returns all Directories. Includes deleted directories if deleted == true.
func (t *Table) List(ctx context.Context, deleted bool) ([]*directory.Directory, error) {
	stmt := spanner.NewStatement("SELECT * FROM Directories WHERE Deleted = FALSE ORDER BY DirectoryID")
	if deleted {
		stmt = spanner.NewStatement("SELECT * FROM Directories ORDER BY DirectoryID")
	}

	ret := []*directory.Directory{}
	rtx := t.client.Single()
	defer rtx.Close()
	err := rtx.Query(ctx, stmt).Do(
		func(r *spanner.Row) error {
			d, err := unpackRow(r)
			if err != nil {
				return err
			}
			ret = append(ret, d)
			return nil
		})
	return ret, err
}

// Write creates a new Directory.
func (t *Table) Write(ctx context.Context, dir *directory.Directory) error {
	// Prepare data.
	keyPB, err := ptypes.MarshalAny(dir.VRFPriv)
	if err != nil {
		return err
	}
	keyData, err := proto.Marshal(keyPB)
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

	m, err := spanner.InsertStruct(table, dirRow{
		DirectoryID:   dir.DirectoryID,
		Map:           tmap,
		Log:           tlog,
		VRFPublicKey:  dir.VRF.GetDer(),
		VRFPrivateKey: keyData,
		MinInterval:   dir.MinInterval.Nanoseconds(),
		MaxInterval:   dir.MaxInterval.Nanoseconds(),
	})
	if err != nil {
		return err
	}

	_, err = t.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// Read retrieves a directory from storage. Returns status.NotFound if the row is deleted.
func (t *Table) Read(ctx context.Context, directoryID string, showDeleted bool) (*directory.Directory, error) {
	rtx := t.client.Single()
	defer rtx.Close()
	row, err := rtx.ReadRow(ctx, table, spanner.Key{directoryID}, dirColumns)
	if err != nil {
		return nil, err
	}
	dir, err := unpackRow(row)
	if err != nil {
		return nil, err
	}
	if !showDeleted && dir.Deleted {
		return nil, status.Errorf(codes.NotFound, "Directory %v is deleted", directoryID)
	}
	return dir, nil
}

// unmarshalAny returns the proto object seralized inside a serialized any.Any.
func unmarshalAny(anyData []byte) (proto.Message, error) {
	var anyPB any.Any
	if err := proto.Unmarshal(anyData, &anyPB); err != nil {
		return nil, err
	}
	var dynamicAny ptypes.DynamicAny
	if err := ptypes.UnmarshalAny(&anyPB, &dynamicAny); err != nil {
		return nil, err
	}
	return dynamicAny.Message, nil
}

// SetDelete deletes or undeletes a directory.
func (t *Table) SetDelete(ctx context.Context, directoryID string, isDeleted bool) error {
	_, err := t.client.Apply(ctx, []*spanner.Mutation{
		spanner.Update(table, []string{"DirectoryID", "Deleted", "DeleteTime"},
			[]interface{}{directoryID, isDeleted, time.Now()}),
	})
	return err
}

// Delete permanently deletes a directory.
func (t *Table) Delete(ctx context.Context, directoryID string) error {
	// This can be an extremely large call due to table interleaving.
	// TODO: Find a different schema that allows incremental deletes.
	_, err := t.client.Apply(ctx, []*spanner.Mutation{
		spanner.Delete(table, spanner.Key{directoryID}),
	})
	return err
}
