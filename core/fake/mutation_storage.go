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
	mtns map[int64][]*pb.EntryUpdate
}

// NewMutationStorage returns a fake mutator.Mutation
func NewMutationStorage() *MutationStorage {
	return &MutationStorage{
		mtns: make(map[int64][]*pb.EntryUpdate),
	}
}

// ReadPage paginates through the list of mutations
func (m *MutationStorage) ReadPage(_ context.Context, mapID, start, end int64, pageSize int32) (int64, []*pb.Entry, error) {
	if start > int64(len(m.mtns[mapID])) {
		panic("start > len(m.mtns[mapID])")
	}
	// Adjust end.
	if end-start > int64(pageSize) {
		end = start + int64(pageSize)
	}
	if end > int64(len(m.mtns[mapID])) {
		end = int64(len(m.mtns[mapID]))
	}
	entryupdates := m.mtns[mapID][start:end]
	entries := make([]*pb.Entry, 0, len(entryupdates))
	for _, e := range entryupdates {
		entries = append(entries, e.Mutation)
	}
	return end, entries, nil
}

// ReadBatch is unimplemented
func (m *MutationStorage) ReadBatch(context.Context, int64, int64, int32) (int64, []*mutator.Mutation, error) {
	return 0, nil, nil
}

// Write stores a mutation
func (m *MutationStorage) Write(_ context.Context, mapID int64, mutation *pb.EntryUpdate) (int64, error) {
	m.mtns[mapID] = append(m.mtns[mapID], mutation)
	return int64(len(m.mtns[mapID])), nil
}
