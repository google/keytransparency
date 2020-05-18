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

// Package batch allows for reading and writing of batches of mutations.
// Each batch of revisions corresponds to a map revision.
package batch

import (
	"context"

	"cloud.google.com/go/spanner"
	"github.com/golang/protobuf/proto" //nolint:staticcheck

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
)

const table = "Batches"

// Table implements sequencer.Batcher
type Table struct {
	client *spanner.Client
}

// New returns a new Table.
func New(client *spanner.Client) *Table {
	return &Table{client: client}
}

// WriteBatchSources saves the the source metadata used to make this revision.
// It is the caller's responsibility to ensure that rev is sequential.
func (t *Table) WriteBatchSources(ctx context.Context, dirID string, rev int64, sources *spb.MapMetadata) error {
	metaBytes, err := proto.Marshal(sources)
	if err != nil {
		return err
	}

	// Cols are columns of the Batches table.
	type Cols struct {
		DirectoryID string
		Revision    int64
		Meta        []byte
	}
	m, err := spanner.InsertStruct(table, Cols{
		DirectoryID: dirID,
		Revision:    rev,
		Meta:        metaBytes,
	})
	if err != nil {
		return err
	}
	_, err = t.client.Apply(ctx, []*spanner.Mutation{m})
	return err
}

// ReadBatch returns the batch definitions for a given revision.
func (t *Table) ReadBatch(ctx context.Context, directoryID string, rev int64) (*spb.MapMetadata, error) {
	rtx := t.client.Single()
	defer rtx.Close()

	var metaBytes []byte
	r, err := rtx.ReadRow(ctx, table, spanner.Key{directoryID, rev}, []string{"Meta"})
	if err != nil {
		return nil, err
	}
	if err := r.ColumnByName("Meta", &metaBytes); err != nil {
		return nil, err
	}
	meta := spb.MapMetadata{}
	if err := proto.Unmarshal(metaBytes, &meta); err != nil {
		return nil, err
	}
	return &meta, nil
}

// HighestRev returns the highest defined revision number for directoryID.
func (t *Table) HighestRev(ctx context.Context, directoryID string) (int64, error) {
	rtx := t.client.Single()
	defer rtx.Close()

	// TODO: Replace with MAX(Revision) when spansql supports aggregate operators.
	stmt := spanner.NewStatement(`SELECT Revision FROM Batches WHERE DirectoryID = @directoryID ORDER BY Revision DESC LIMIT 1`)
	stmt.Params["directoryID"] = directoryID
	var rev int64
	err := rtx.Query(ctx, stmt).Do(
		func(row *spanner.Row) error {
			return row.Columns(&rev)
		})
	return rev, err
}
