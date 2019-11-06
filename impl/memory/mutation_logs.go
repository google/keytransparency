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

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

var clock = time.Unix(10, 0) // Start our clock at an arbitrary, non-zero place.

// NewMutationLogs creates a new fake MutationLogs.
func NewMutationLogs() MutationLogs {
	return make(MutationLogs)
}

type batch struct {
	time time.Time
	msgs []*mutator.LogMessage
}

// MutationLogs is a fake, in-memory implementation of a keyserver.MutationLogss.
// All requests are presumed to be for the same domainID.
// TODO(gbelvin): Support multiple domainIDs, if tests call for it.
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

// Send stores a batch of mutations in a random logID.
func (m MutationLogs) Send(_ context.Context, _ string, logID int64, mutation ...*pb.EntryUpdate) (time.Time, error) {
	clock = clock.Add(time.Second)
	ts := clock
	// Only save the Merkle tree bits.
	entries := make([]*pb.SignedEntry, 0, len(mutation))
	for _, i := range mutation {
		entries = append(entries, i.Mutation)
	}

	logShard := m[logID]
	if len(logShard) > 0 && logShard[len(logShard)-1].time.After(ts) {
		return time.Time{}, fmt.Errorf("inserting mutation entry %v out of order", ts)
	}

	// Convert []SignedEntry into []LogMessage for storage.
	msgs := make([]*mutator.LogMessage, 0, len(entries))
	for _, e := range entries {
		msgs = append(msgs, &mutator.LogMessage{ID: ts, Mutation: e})
	}
	m[logID] = append(logShard, batch{time: ts, msgs: msgs})
	return ts, nil
}

// ReadLog returns mutations between [low, high).  Always returns complete batches.
// ReadLog will return more items than batchSize if necessary to return a complete batch.
func (m MutationLogs) ReadLog(_ context.Context, _ string,
	logID int64, low, high time.Time, batchSize int32) ([]*mutator.LogMessage, error) {
	logShard := m[logID]
	if len(logShard) == 0 || batchSize == 0 {
		return nil, nil
	}
	start := sort.Search(len(logShard), func(i int) bool { return !logShard[i].time.Before(low) })
	end := sort.Search(len(logShard), func(i int) bool { return !logShard[i].time.Before(high) })
	// If the search is unsuccessful, i will be equal to len(logShard).
	if start == len(logShard) && logShard[start].time.Before(low) {
		return nil, fmt.Errorf("invalid argument: low: %v, want <= max watermark: %v", low, logShard[start].time)
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

// HighWatermark returns the highest timestamp batchSize items beyond start.
func (m MutationLogs) HighWatermark(_ context.Context, _ string, logID int64, start time.Time,
	batchSize int32) (int32, time.Time, error) {
	logShard := m[logID]
	i := sort.Search(len(logShard), func(i int) bool { return !logShard[i].time.Before(start) })

	count := int32(0)
	high := start // Preserve start time if there are no rows to process.
	for ; i < len(logShard) && count < batchSize; i++ {
		high = logShard[i].time.Add(time.Nanosecond) // Returns exclusive n + 1
		count += int32(len(logShard[i].msgs))
	}
	return count, high, nil
}
