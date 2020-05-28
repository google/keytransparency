// Copyright 2019 Google Inc. All Rights Reserved.
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

// Package memory supplies fake in-memory implementations for testing purposes.
package memory

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/water"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

var clock = uint64(10) // Start logical clock at an arbitrary, non-zero place.

// NewMutationLogs creates a new fake MutationLogs.
func NewMutationLogs() MutationLogs {
	return make(MutationLogs)
}

type batch struct {
	wm   water.Mark
	msgs []*mutator.LogMessage
}

// MutationLogs is a fake, in-memory implementation of a keyserver.MutationLogss.
// All requests are presumed to be for the same domainID.
// TODO(gbelvin): Support multiple domainIDs, if tests call for it.
// MutationLogs is NOT threadsafe.
type MutationLogs map[int64][]batch // Map of logID to Slice of LogMessages

// AddLogs adds logIDs to the mutation database.
func (m MutationLogs) AddLogs(_ context.Context, _ string, logIDs ...int64) error {
	for _, logID := range logIDs {
		m[logID] = make([]batch, 0)
	}
	return nil
}

// ListLogs returns a sorted list of logIDs.
func (m MutationLogs) ListLogs(_ context.Context, _ string, writable bool) ([]int64, error) {
	logIDs := []int64{}
	for logID := range m {
		logIDs = append(logIDs, logID)
	}
	sort.Slice(logIDs, func(a, b int) bool { return logIDs[a] < logIDs[b] })
	return logIDs, nil
}

// SendBatch stores a batch of mutations in a given logID.
func (m MutationLogs) SendBatch(_ context.Context, _ string, logID int64, mutations []*pb.EntryUpdate) (water.Mark, error) {
	wm := water.NewMark(clock)
	clock++
	// Only save the Merkle tree bits.
	entries := make([]*pb.SignedEntry, 0, len(mutations))
	for _, i := range mutations {
		entries = append(entries, i.Mutation)
	}

	logShard := m[logID]
	if len(logShard) > 0 && logShard[len(logShard)-1].wm.Compare(wm) > 0 {
		return water.Mark{}, fmt.Errorf("inserting mutation entry %v out of order", wm)
	}

	// Convert []SignedEntry into []LogMessage for storage.
	msgs := make([]*mutator.LogMessage, 0, len(entries))
	for i, e := range entries {
		m := &mutator.LogMessage{
			LogID:     logID,
			ID:        wm,
			LocalID:   int64(i),
			CreatedAt: time.Now(),
			Mutation:  e,
		}
		msgs = append(msgs, m)
	}
	m[logID] = append(logShard, batch{wm: wm, msgs: msgs})
	return wm, nil
}

// ReadLog returns mutations between [low, high).  Always returns complete batches.
// ReadLog will return more items than batchSize if necessary to return a complete batch.
func (m MutationLogs) ReadLog(_ context.Context, _ string,
	logID int64, low, high water.Mark, batchSize int32) ([]*mutator.LogMessage, error) {
	logShard := m[logID]
	if len(logShard) == 0 || batchSize == 0 {
		return nil, nil
	}
	start := sort.Search(len(logShard), func(i int) bool { return logShard[i].wm.Compare(low) >= 0 })
	end := sort.Search(len(logShard), func(i int) bool { return logShard[i].wm.Compare(high) >= 0 })
	// If the search is unsuccessful, i will be equal to len(logShard).
	if start == len(logShard) && logShard[start-1].wm.Compare(low) < 0 {
		return nil, fmt.Errorf("invalid argument: low: %v, want <= max watermark: %v", low, logShard[start-1].wm)
	}
	out := make([]*mutator.LogMessage, 0, batchSize)
	for i := start; i < end; i++ {
		out = append(out, logShard[i].msgs...)
		if int32(len(out)) >= batchSize {
			break
		}
	}
	return out, nil
}

// HighWatermark returns the highest watermark batchSize items beyond start.
func (m MutationLogs) HighWatermark(_ context.Context, _ string, logID int64, start water.Mark,
	batchSize int32) (int32, water.Mark, error) {
	logShard := m[logID]
	i := sort.Search(len(logShard), func(i int) bool { return logShard[i].wm.Compare(start) >= 0 })

	count := int32(0)
	high := start // Preserve start watermark if there are no rows to process.
	for ; i < len(logShard) && count < batchSize; i++ {
		high = logShard[i].wm.Add(1) // Return the exclusive watermark.
		count += int32(len(logShard[i].msgs))
	}
	return count, high, nil
}
