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
	"context"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	"github.com/google/keytransparency/core/mutator"
)

// MutationStorage implements mutator.Mutation
type MutationStorage struct {
	mtns map[string][]*pb.EntryUpdate
}

// NewMutationStorage returns a fake mutator.Mutation
func NewMutationStorage() *MutationStorage {
	return &MutationStorage{
		mtns: make(map[string][]*pb.EntryUpdate),
	}
}

// ReadPage paginates through the list of mutations
func (m *MutationStorage) ReadPage(_ context.Context, domainID string, start, end int64, pageSize int32) (int64, []*pb.Entry, error) {
	if start > int64(len(m.mtns[domainID])) {
		panic("start > len(m.mtns[domainID])")
	}
	// Adjust end.
	if end-start > int64(pageSize) {
		end = start + int64(pageSize)
	}
	if end > int64(len(m.mtns[domainID])) {
		end = int64(len(m.mtns[domainID]))
	}
	entryUpdates := m.mtns[domainID][start:end]
	mutations := make([]*pb.Entry, 0, len(entryUpdates))
	for _, e := range entryUpdates {
		mutations = append(mutations, e.Mutation)
	}
	return end, mutations, nil
}

// ReadBatch is unimplemented
func (m *MutationStorage) ReadBatch(context.Context, string, int64, int32) (int64, []*mutator.QueueMessage, error) {
	return 0, nil, nil
}

// Write stores a mutation
func (m *MutationStorage) Write(_ context.Context, domainID string, mutation *pb.EntryUpdate) (int64, error) {
	m.mtns[domainID] = append(m.mtns[domainID], mutation)
	return int64(len(m.mtns[domainID])), nil
}
