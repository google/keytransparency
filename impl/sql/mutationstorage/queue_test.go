// Copyright 2018 Google Inc. All Rights Reserved.
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

package mutationstorage

import (
	"context"
	"testing"
	"time"

	"github.com/google/keytransparency/core/mutator"
)

var (
	min = time.Millisecond * 2
	max = time.Millisecond * 10
)

func TestRecieverTime(t *testing.T) {
	ctx := context.Background()
	m, err := New(newDB(t))
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	now := time.Now()
	for i, tc := range []struct {
		want int
		last time.Time
		wait time.Duration
	}{
		// Fresh start (last successful epoch not yet created):
		{want: 0, last: now, wait: min * 2},
		{want: 1, last: now, wait: max + min},
		{want: 2, last: now, wait: max*2 - min},
		{want: 4, last: now, wait: max*3 + min},
		// Resume from last epoch in the past:
		{want: 1, last: now.Add(-max), wait: max / 2},
		{want: 1, last: now.Add(max * -6), wait: max / 2},
	} {
		var count int
		start := int64(0)
		r := m.NewReciever(ctx, tc.last, mapID, start, func([]*mutator.QueueMessage) error {
			count++
			return nil
		}, mutator.RecieverOptions{
			MaxBatchSize: 1,
			Period:       min,
			MaxPeriod:    max,
		})
		time.Sleep(tc.wait)
		r.Close()
		if got, want := count, tc.want; got != want {
			t.Errorf("test: %d: recieveFunc called %d times, want %v", i, got, want)
		}
	}
}

// parseTime creates a time.Time from a time.RFC3339 formatted string.
func parseTime(ts string) time.Time {
	ti, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic("parseTime(_) expects time.RFC3339 formatted time strings, got: " + ts)
	}
	return ti
}
