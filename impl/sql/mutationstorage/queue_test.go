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
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/keytransparency/core/mutator"

	"github.com/golang/protobuf/proto"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	_ "github.com/mattn/go-sqlite3"
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
		last      time.Time
		C         chan time.Time
		wantCalls int
	}{
		{desc: "Do nothing", wantCalls: 0, last: now, C: fake},
		{desc: "About to blow MMD", wantCalls: 1, last: now.Add(max * -2), C: fake},
		{desc: "Max tick", wantCalls: 1, last: now, C: maxC},
		{desc: "Min tick, no data", wantCalls: 0, last: now, C: minC},
		{desc: "Min tick, some data", wantCalls: 1, send: 1, last: now, C: minC},
		{desc: "Min tick, multiple batches", wantCalls: 2, send: 2, last: now, C: minC},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			for i := 0; i < tc.send; i++ {
				if err := m.Send(ctx, domainID, &pb.EntryUpdate{}); err != nil {
					t.Fatalf("Could not fill queue: %v", err)
				}
			}

			var wg sync.WaitGroup
			wg.Add(tc.wantCalls)
			count := 0
			r, ok := m.NewReceiver(ctx, tc.last, domainID, func([]*mutator.QueueMessage) error {
				count++
				wg.Done()
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

func genUpdate(i int) *pb.EntryUpdate {
	return &pb.EntryUpdate{
		Mutation: genMutation(i),
		Committed: &pb.Committed{
			Key:  []byte(fmt.Sprintf("nonce%d", i)),
			Data: []byte(fmt.Sprintf("data%d", i)),
		},
	}
}

func fillQueue(ctx context.Context, m mutator.MutationQueue) error {
	for _, update := range []*pb.EntryUpdate{
		genUpdate(1),
		genUpdate(2),
		genUpdate(3),
		genUpdate(4),
		genUpdate(5),
	} {
		if err := m.Send(ctx, domainID, update); err != nil {
			return err
		}
	}
	return nil
}

func TestQueueSendBatch(t *testing.T) {
	ctx := context.Background()
	db := newDB(t)
	m, err := New(db)
	if err != nil {
		t.Fatalf("Failed to create mutations: %v", err)
	}

	if err := fillQueue(ctx, m); err != nil {
		t.Fatalf("Failed to write updates: %v", err)
	}

	for _, tc := range []struct {
		description string
		updates     []*pb.EntryUpdate
		batchSize   int32
	}{
		{
			description: "read half",
			updates: []*pb.EntryUpdate{
				genUpdate(1),
				genUpdate(2),
				genUpdate(3),
			},
			batchSize: 3,
		},
		{
			description: "read rest",
			updates: []*pb.EntryUpdate{
				genUpdate(4),
				genUpdate(5),
			},
			batchSize: 3,
		},
		{
			description: "empty queue",
			updates:     nil,
			batchSize:   10,
		},
	} {
		wg := new(sync.WaitGroup)
		wg.Add(1)
		t.Run(tc.description, func(t *testing.T) {
			r, ok := m.NewReceiver(ctx, time.Now(), domainID, func(msgs []*mutator.QueueMessage) error {
				if got, want := len(msgs), len(tc.updates); got != want {
					t.Errorf("len(msgs): %v, want %v", got, want)
				}
				for i, msg := range msgs {
					if got, want := msg.Mutation, tc.updates[i].Mutation; !proto.Equal(got, want) {
						t.Errorf("msg[%v].Mutation: %v, want %v", i, got, want)
					}
					if got, want := msg.ExtraData, tc.updates[i].Committed; !proto.Equal(got, want) {
						t.Errorf("msg[%v].ExtraData: %v, want %v", i, got, want)
					}
				}
				wg.Done()
				return nil
			}, mutator.ReceiverOptions{
				MaxBatchSize: tc.batchSize,
				// With Period=MaxPeriod, one batch will be force-sent.
				Period:    60 * time.Hour,
				MaxPeriod: 60 * time.Hour,
			}).(*Receiver)
			if !ok {
				t.Fatalf("Failed type assertion: %T", r)
			}
			wg.Wait()
			r.Close()
		})
	}
}
