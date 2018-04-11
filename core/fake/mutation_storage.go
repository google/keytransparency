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
	"fmt"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// MutationStorage implements mutator.Mutation
type MutationStorage struct {
	// mtns is a map of domains to epoch numbers to a list of mutations.
	mtns map[string]map[int64][]*pb.Entry
}

// NewMutationStorage returns a fake mutator.Mutation
func NewMutationStorage() *MutationStorage {
	return &MutationStorage{
		mtns: make(map[string]map[int64][]*pb.Entry),
	}
}

// ReadPage paginates through the list of mutations
func (m *MutationStorage) ReadPage(_ context.Context, domainID string, revision, start int64, pageSize int32) (int64, []*pb.Entry, error) {
	domain, ok := m.mtns[domainID]
	if !ok {
		return 0, nil, fmt.Errorf("DomainID %v not found", domainID)
	}
	mutationList, ok := domain[revision]
	if !ok {
		return 0, nil, fmt.Errorf("DomainID: %v, revision %v not found", domainID, revision)
	}
	if int(start) > len(mutationList) {
		return start, nil, nil
	}
	end := int(start) + int(pageSize)
	if end > len(mutationList) {
		end = len(mutationList)
	}
	return int64(end), mutationList[int(start):end], nil
}

// WriteBatch stores a set of mutations that are associated with a revision.
func (m *MutationStorage) WriteBatch(_ context.Context, domainID string, revision int64, mutations []*pb.Entry) error {
	if _, ok := m.mtns[domainID]; !ok {
		m.mtns[domainID] = make(map[int64][]*pb.Entry)
	}
	m.mtns[domainID][revision] = mutations
	return nil
}
