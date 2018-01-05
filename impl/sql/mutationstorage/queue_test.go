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
		desc  string
		send  int
		start int64
		last  time.Time
		C     chan time.Time
		want  int
	}{
		{desc: "Do nothing", want: 0, last: now, C: fake},
		{desc: "About to blow MMD", want: 1, last: now.Add(max * -2), C: fake},
		{desc: "Max tick", want: 1, last: now, C: maxC},
		{desc: "Min tick, no data", want: 0, last: now, C: minC},
		{desc: "Min tick, some data", want: 1, send: 1, last: now, C: minC},
		{desc: "Min tick, multiple batches", want: 2, send: 2, start: 1, last: now, C: minC},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			for i := 0; i < tc.send; i++ {
				if err := m.Send(ctx, mapID, &pb.EntryUpdate{}); err != nil {
					t.Fatalf("Could not fill queue: %v", err)
				}
			}

			var wg sync.WaitGroup
			wg.Add(tc.want)
			count := 0
			receiver := m.NewReceiver(ctx, tc.last, mapID, tc.start, func(msgs []*mutator.QueueMessage) error {
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
			})
			// Take control of channels.
			r, ok := (receiver).(*Receiver)
			if !ok {
				t.Fatalf("reciever is type %T", receiver)
			}
			r.ticker.C = minC
			r.maxTicker.C = maxC

			tc.C <- time.Now()
			wg.Wait()
			r.Close()

			if got, want := count, tc.want; got != want {
				t.Errorf("recieveFunc called %d times, want %v", got, want)
			}
		})
	}
}
