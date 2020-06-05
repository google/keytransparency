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

package impl

import (
	"context"
	"fmt"

	"cloud.google.com/go/spanner"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/core/water"
	"github.com/google/keytransparency/impl/mysql/mutationstorage"
	"github.com/google/keytransparency/impl/spanner/batch"
	"github.com/google/keytransparency/impl/spanner/directory"
	"github.com/google/keytransparency/impl/spanner/mutations"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	dinterface "github.com/google/keytransparency/core/directory"
	ktsql "github.com/google/keytransparency/impl/mysql"
	sqld "github.com/google/keytransparency/impl/mysql/directory"
)

// Storage holds an abstract storage implementation
type Storage struct {
	Directories dinterface.Storage
	Logs        interface {
		sequencer.LogsReader

		// Copied methods from adminserver.LogsAdmin because of duplicate method.

		// AddLogs creates and adds new logs for writing to a directory.
		AddLogs(ctx context.Context, directoryID string, logIDs ...int64) error
		// SetWritable enables or disables new writes from going to logID.
		SetWritable(ctx context.Context, directoryID string, logID int64, enabled bool) error

		// Copied methods from keyserver.MutationLogs
		SendBatch(ctx context.Context, directoryID string, logID int64, batch []*pb.EntryUpdate) (water.Mark, error)
	}
	Batches     sequencer.Batcher
	healthCheck func() error
	Close       func()
}

// HealthCheck reports on the health of the underlying database connection.
func (s *Storage) HealthCheck() error { return s.healthCheck() }

// NewStorage returns a Storage with the requested engine.
func NewStorage(ctx context.Context, engine, db string) (*Storage, error) {
	switch engine {
	case "mysql":
		return mysqlStorage(db)
	case "spanner":
		return spannerStorage(ctx, db)
	default:
		return nil, fmt.Errorf("unknown db engine %s", engine)
	}
}

func spannerStorage(ctx context.Context, db string) (*Storage, error) {
	spanClient, err := spanner.NewClient(ctx, db)
	if err != nil {
		return nil, err
	}
	return &Storage{
		Directories: directory.New(spanClient),
		Batches:     batch.New(spanClient),
		Logs:        mutations.New(spanClient),
		healthCheck: func() error { return nil },
		Close:       spanClient.Close,
	}, nil
}

func mysqlStorage(db string) (*Storage, error) {
	sqldb, err := ktsql.Open(db)
	if err != nil {
		return nil, err
	}
	directories, err := sqld.NewStorage(sqldb)
	if err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("failed to create directory storage: %w", err)
	}
	logs, err := mutationstorage.New(sqldb)
	if err != nil {
		sqldb.Close()
		return nil, fmt.Errorf("failed to create mutations storage: %w", err)
	}
	return &Storage{
		Directories: directories,
		Batches:     logs,
		Logs:        logs,
		healthCheck: sqldb.Ping,
		Close:       func() { sqldb.Close() },
	}, nil
}
