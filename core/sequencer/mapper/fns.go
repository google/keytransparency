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

package mapper

import (
	"context"

	"github.com/gogo/protobuf/proto"
	"github.com/google/keytransparency/core/directory"

	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tpb "github.com/google/trillian"
)

// During distributed execution, the functions here are called by JSON
// deserializing the Fn structs and executing their functions.  Any supporting
// objects that are not JSON serializable must be set via accessor functions.
//
// Flags are only passed to the master job.

// Dialer returns gRPC connections to the Trillian backends.
type Dialer interface {
	// Map returns a connection to the TrillianMap.
	Map(ctx context.Context, spec string) (func(), tpb.TrillianMapClient, error)
	Admin(ctx context.Context, spec string) (func(), tpb.TrillianAdminClient, error)
	Directory(addr string) (func(), directory.Storage, error)
}

var dial Dialer

// SetDialer allows tests and production environments to use their own methods
// for connecting to Trillian Servers.
func SetDialer(d Dialer) { dial = d }

// WriteMapFn writes sets of map leaves to the Trillian Map.
// UserFunctions must be JSON serializable.
type WriteMapFn struct {
	closeMapConn   func()
	closeAdminConn func()
	closeDB        func()
	factory        *ClientFactory // Won't make it past serialization.
	MapSpec        string         `json:"mapspec"`
	DBPath         string         `json:"dbpath"`
	DirectoryID    string         `json:"directory_id"`
}

// Setup initializes network and database connections.
func (fn *WriteMapFn) Setup(ctx context.Context) error {
	if fn.factory == nil {
		// Distributed mode.
		closeMapConn, tmap, err := dial.Map(ctx, fn.MapSpec)
		if err != nil {
			return err
		}
		fn.closeMapConn = closeMapConn
		closeAdminConn, tadmin, err := dial.Admin(ctx, fn.MapSpec)
		if err != nil {
			return err
		}
		fn.closeAdminConn = closeAdminConn
		closeDB, directories, err := dial.Directory(fn.DBPath)
		if err != nil {
			return err
		}
		fn.closeDB = closeDB

		fn.factory = NewClientFactory(tmap, tadmin, directories)
	}
	return nil
}

// Teardown closes all resources opened by Setup().
func (fn *WriteMapFn) Teardown() {
	if fn.closeMapConn != nil {
		fn.closeMapConn()
	}
	if fn.closeAdminConn != nil {
		fn.closeAdminConn()
	}
	if fn.closeDB != nil {
		fn.closeDB()
	}
}

// ProcessElement calls SetLeaves with the provided slice of []*tpb.MapLeaf.
func (fn *WriteMapFn) ProcessElement(ctx context.Context, leaves []*tpb.MapLeaf,
	meta *spb.MapMetadata, directoryID string) error {

	metadata, err := proto.Marshal(meta)
	if err != nil {
		return err
	}

	mapClient, err := fn.factory.MakeMapClient(ctx, directoryID)
	if err != nil {
		return err
	}
	_, err = mapClient.SetLeaves(ctx, leaves, metadata)
	return err
}
