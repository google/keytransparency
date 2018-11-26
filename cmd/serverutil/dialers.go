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

package serverutil

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/google/keytransparency/impl/sql/directory"
	"github.com/google/keytransparency/impl/sql/engine"
	"google.golang.org/grpc"

	dir "github.com/google/keytransparency/core/directory"
	tpb "github.com/google/trillian"
)

// OpenSourceDialer supplies gRPC dialing functions and initializers from the /impl directory.
type OpenSourceDialer struct{}

// Map return a close function and a TrillianMapClient.
func (OpenSourceDialer) Map(ctx context.Context, spec string) (func(), tpb.TrillianMapClient, error) {
	conn, err := grpc.Dial(spec, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("grpc.Dial(%v): %v", spec, err)
	}
	return func() { conn.Close() }, tpb.NewTrillianMapClient(conn), nil
}

// Admin return a close function and a TrillianAdminClient.
func (OpenSourceDialer) Admin(ctx context.Context, spec string) (func(), tpb.TrillianAdminClient, error) {
	conn, err := grpc.Dial(spec, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("grpc.Dial(%v): %v", spec, err)
	}
	return func() { conn.Close() }, tpb.NewTrillianAdminClient(conn), nil
}

// Directory returns a close function and a directory.storage object.
func (OpenSourceDialer) Directory(DBPath string) (func(), dir.Storage, error) {
	db, err := sql.Open(engine.DriverName, DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		return nil, nil, fmt.Errorf("db.Ping(): %v", err)
	}
	directoryStorage, err := directory.NewStorage(db)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create directory storage object: %v", err)
	}
	return func() { db.Close() }, directoryStorage, nil
}
