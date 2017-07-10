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

package appender

import (
	"database/sql"
	"encoding/json"
	"fmt"

	"github.com/google/keytransparency/core/admin"

	"golang.org/x/net/context"
)

// Trillian sends sequenced items to a Trillian log.
type Trillian struct {
	admin admin.Admin
}

// NewTrillian creates a new client to a Trillian Log.
func NewTrillian(admin admin.Admin) Remote {
	return &Trillian{
		admin: admin,
	}
}

// Append sends obj to Trillian as a json object at the given epoch index.
func (t *Trillian) Write(ctx context.Context, logID, epoch int64, obj interface{}) error {
	log, err := t.admin.LogClient(logID)
	if err != nil {
		return err
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	// TODO(gbelvin): Add leaf at a specific index. trillian#423
	// Insert index = epoch -1. MapRevisions start at 1. Log leaves start at 0.
	if err := log.AddLeaf(ctx, b); err != nil {
		return err
	}
	return nil
}

// Epoch sets object to the value at a particular index. Returns associated data with that index, an SCT.
// Trillian does not return SCTs so this implementation always returns nil.
func (t *Trillian) Read(ctx context.Context, logID, epoch int64, obj interface{}) error {
	log, err := t.admin.LogClient(logID)
	if err != nil {
		return err
	}

	leaves, err := log.ListByIndex(ctx, epoch, 1)
	if err != nil {
		return err
	}
	if len(leaves) != 1 {
		return fmt.Errorf("Leaf not returned")
	}
	// Unmarshal leaf into obj.
	if err := json.Unmarshal(leaves[0].LeafValue, &obj); err != nil {
		return err
	}
	return nil
}

// Latest retrieves the last object. Returns sql.ErrNoRows if empty.
func (t *Trillian) Latest(ctx context.Context, logID int64, obj interface{}) (int64, error) {
	log, err := t.admin.LogClient(logID)
	if err != nil {
		return 0, err
	}

	if err := log.UpdateRoot(ctx); err != nil {
		return 0, err
	}
	epoch := log.Root().TreeSize - 1
	if epoch < 0 {
		return 0, sql.ErrNoRows
	}
	if err := t.Read(ctx, logID, epoch, obj); err != nil {
		return 0, err
	}
	return epoch, nil

}
