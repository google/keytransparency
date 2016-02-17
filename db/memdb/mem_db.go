// Copyright 2015 Google Inc. All Rights Reserved.
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
package memdb

import (
	"crypto/sha512"

	"github.com/google/e2e-key-server/db"

	"golang.org/x/net/context"
)

const IndexSize = sha512.Size256
const CommitmentSize = sha512.Size256

type MemDB struct {
	queue       chan []byte
	leaves      map[[IndexSize]byte][]byte
	commitments map[[CommitmentSize]byte]db.Commitment
}

// Create creates a storage object from an existing db connection.
func New() *MemDB {
	return &MemDB{
		queue:       make(chan []byte, 100),
		leaves:      make(map[[IndexSize]byte][]byte),
		commitments: make(map[[CommitmentSize]byte]db.Commitment),
	}
}

func (d *MemDB) QueueMutation(ctx context.Context, index, mutation []byte) error {
	d.queue <- mutation
	return nil
}

func (d *MemDB) Queue() <-chan []byte {
	return d.queue
}

func (d *MemDB) WriteCommitment(ctx context.Context, commitment, key, value []byte) error {
	var k [CommitmentSize]byte
	copy(k[:], commitment[:CommitmentSize])
	c := db.Commitment{key, value}
	d.commitments[k] = c
	return nil
}

func (d *MemDB) ReadCommitment(ctx context.Context, commitment []byte) (db.Commitment, error) {
	var k [CommitmentSize]byte
	copy(k[:], commitment[:CommitmentSize])
	return d.commitments[k], nil
}
