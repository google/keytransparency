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
	"sync"
	"testing"
	"time"

	"github.com/google/keytransparency/core/mutator"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
)

func TestRecieverChan(t *testing.T) {
	ctx := context.Background()
	m, err := New(newDB(t))
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	min := 10 * time.Hour
	max := 60 * time.Hour
	minC := make(chan time.Time)
	maxC := make(chan time.Time)
	fake := make(chan time.Time, 10)
	now := time.Now()
	for _, tc := range []struct {
		desc      string
		send      int
		start     int64
		last      time.Time
		C         chan time.Time
		wantCalls int
	}{
		{desc: "Do nothing", wantCalls: 0, last: now, C: fake},
		{desc: "About to blow MMD", wantCalls: 1, last: now.Add(max * -2), C: fake},
		{desc: "Max tick", wantCalls: 1, last: now, C: maxC},
		{desc: "Min tick, no data", wantCalls: 0, last: now, C: minC},
		{desc: "Min tick, some data", wantCalls: 1, send: 1, last: now, C: minC},
		{desc: "Min tick, multiple batches", wantCalls: 2, send: 2, start: 1, last: now, C: minC},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			for i := 0; i < tc.send; i++ {
				if err := m.Send(ctx, mapID, &pb.EntryUpdate{}); err != nil {
					t.Fatalf("Could not fill queue: %v", err)
				}
			}

			var wg sync.WaitGroup
			wg.Add(tc.wantCalls)
			count := 0
			r, ok := m.NewReceiver(ctx, tc.last, mapID, tc.start, func(msgs []*mutator.QueueMessage) error {
				count++
				wg.Done()
				t.Logf("Callback %v", count)
				for _, i := range msgs {
					t.Logf("   with item %v", i.ID)
				}
				return nil
			}, mutator.ReceiverOptions{
				MaxBatchSize: 1,
				Period:       min,
				MaxPeriod:    max,
			}).(*Receiver)
			if !ok {
				t.Fatalf("receiver is: %T", r)
			}
			r.ticker.C = minC
			r.maxTicker.C = maxC

			tc.C <- time.Now()
			wg.Wait()
			r.Close()

			if got, want := count, tc.wantCalls; got != want {
				t.Errorf("receiveFunc called %d times, want %v", got, want)
			}
		})
	}
}
