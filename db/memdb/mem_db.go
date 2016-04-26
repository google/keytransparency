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

// package memdb implements an in-memory fake database for proof-of-concept
// purposes.
package memdb

import (
	"github.com/google/e2e-key-server/db"

	"golang.org/x/net/context"
)

type MemDB struct {
	queue chan *db.Mutation
}

// Create creates a storage object from an existing db connection.
func New() *MemDB {
	return &MemDB{
		queue: make(chan *db.Mutation, 100),
	}
}

func (d *MemDB) QueueMutation(ctx context.Context, index, mutation []byte) error {
	d.queue <- &db.Mutation{index, mutation, make(chan error)}
	return nil
}

func (d *MemDB) Queue() <-chan *db.Mutation {
	return d.queue
}
