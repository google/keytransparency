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

// NewMutationLog creates a new fake MutationLog
func NewMutationLog() MutationLog {
	return make(MutationLog)
}

// MutationLog is a fake implementation of keyserver.
type batch struct {
	time time.Time
	msgs []*mutator.LogMessage
}

// MutationLog is a fake, in-memory implementation of keyserver.MutationLogs
type MutationLog map[int64][]batch // Map of logID to Slice of LogMessages

// AddLogs to the mutation database.
func (m MutationLog) AddLogs(ctx context.Context, directoryID string, logIDs ...int64) error {
	for _, logID := range logIDs {
		m[logID] = make([]batch, 0)
	}
	return nil
}

// AddLogs to the mutation database.
func (m MutationLog) ListLogs(ctx context.Context, directoryID string, writable bool) ([]int64, error) {
	logIDs := []int64{}
	for logID := range m {
		logIDs = append(logIDs, logID)
	}
	sort.Slice(logIDs, func(a, b int) bool { return logIDs[a] < logIDs[b] })
	return logIDs, nil
}

// Send a batch of mutations to a random log.
func (m MutationLog) Send(ctx context.Context, dirID string, mutation ...*pb.EntryUpdate) (int64, time.Time, error) {
	// Select a random logID
	var logID int64
	for i := range m {
		logID = i
		break
	}
	ts := time.Now()
	// Remove the PII contained in EntryUpdate. Only save the merkle tree bits.
	entries := make([]*pb.SignedEntry, 0, len(mutation))
	for _, i := range mutation {
		entries = append(entries, i.Mutation)
	}
	m.SendAt(logID, ts, entries)
	return logID, ts, nil
}

// SendAt sends a batch of mutations with a given timestamp.
func (m MutationLog) SendAt(logID int64, ts time.Time, entries []*pb.SignedEntry) {
	logShard := m[logID]
	if len(logShard) > 0 && logShard[len(logShard)-1].time.After(ts) {
		panic(fmt.Sprintf("inserting mutation entry %v out of order", ts))
	}

	// Convert []SignedEntry into []LogMessage for storage.
	msgs := make([]*mutator.LogMessage, 0, len(entries))
	for _, e := range entries {
		msgs = append(msgs, &mutator.LogMessage{ID: ts, Mutation: e})
	}
	m[logID] = append(logShard, batch{time: ts, msgs: msgs})
}

// ReadLog returns mutations between low, and high. Always returns complete batches.
func (m MutationLog) ReadLog(ctx context.Context, dirID string,
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
	count := int32(0)
	for i := start; i < end; i++ {
		out = append(out, logShard[i].msgs...)
		count += int32(len(logShard[i].msgs))
		if count >= batchSize {
			break
		}
	}
	return out, nil
}

// HighWatermark returns the highest timestamp batchSize items beyond start.
func (m MutationLog) HighWatermark(_ context.Context, _ string, logID int64, start time.Time,
	batchSize int32) (int32, time.Time, error) {
	logShard := m[logID]
	i := sort.Search(len(logShard), func(i int) bool { return !logShard[i].time.Before(start) })

	count := int32(0)
	high := start // Preserve start time if there are no rows to process
	for ; i < len(logShard) && count < batchSize; i++ {
		high = logShard[i].time.Add(time.Nanosecond) // Returns exclusive n + 1
		count += int32(len(logShard[i].msgs))
	}
	return count, high, nil
}
