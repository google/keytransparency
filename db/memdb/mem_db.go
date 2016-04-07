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
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	"golang.org/x/net/context"

	cm "github.com/google/e2e-key-server/db/commitments"
)

const CommitmentSize = cm.Size

type MemDB struct {
	queue       chan *db.Mutation
	commitments map[[CommitmentSize]byte]cm.Commitment
}

// Create creates a storage object from an existing db connection.
func New() *MemDB {
	return &MemDB{
		queue:       make(chan *db.Mutation, 100),
		commitments: make(map[[CommitmentSize]byte]cm.Commitment),
	}
}

func (d *MemDB) QueueMutation(ctx context.Context, index, mutation []byte) error {
	d.queue <- &db.Mutation{index, mutation, make(chan error)}
	return nil
}

func (d *MemDB) Queue() <-chan *db.Mutation {
	return d.queue
}

func (d *MemDB) WriteCommitment(ctx context.Context, commitment, key, value []byte) error {
	var k [CommitmentSize]byte
	copy(k[:], commitment[:CommitmentSize])
	d.commitments[k] = cm.Commitment{key, value}
	return nil
}

func (d *MemDB) ReadCommitment(ctx context.Context, commitment []byte) (*cm.Commitment, error) {
	var k [CommitmentSize]byte
	copy(k[:], commitment[:CommitmentSize])
	c, ok := d.commitments[k]
	if !ok {
		return nil, grpc.Errorf(codes.NotFound, "Commitment %v not found", commitment)
	}
	return &c, nil
}
