// Copyright 2017 Google Inc. All Rights Reserved.
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

package fake

import (
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	"github.com/google/keytransparency/core/transaction"
)

// MutationStorage implements mutator.Mutation
type MutationStorage struct {
	mtns map[int64][]*pb.Entry
}

// NewMutationStorage returns a fake mutator.Mutation
func NewMutationStorage() *MutationStorage {
	return &MutationStorage{
		mtns: make(map[int64][]*pb.Entry),
	}
}

// ReadRange returns the list of mutations
func (m *MutationStorage) ReadRange(txn transaction.Txn, mapID int64, startSequence uint64, endSequence uint64, count int32) (uint64, []*pb.Entry, error) {
	if startSequence > uint64(len(m.mtns[mapID])) {
		panic("startSequence > len(m.mtns[mapID])")
	}
	// Adjust endSequence.
	if endSequence-startSequence > uint64(count) {
		endSequence = startSequence + uint64(count)
	}
	if endSequence > uint64(len(m.mtns[mapID])) {
		endSequence = uint64(len(m.mtns[mapID]))
	}
	return endSequence, m.mtns[mapID][startSequence:endSequence], nil
}

// ReadAll is unimplemented
func (m *MutationStorage) ReadAll(txn transaction.Txn, mapID int64, startSequence uint64) (uint64, []*pb.Entry, error) {
	return 0, nil, nil
}

// Write stores a mutation
func (m *MutationStorage) Write(txn transaction.Txn, mapID int64, mutation *pb.Entry) (uint64, error) {
	m.mtns[mapID] = append(m.mtns[mapID], mutation)
	return uint64(len(m.mtns[mapID])), nil
}
