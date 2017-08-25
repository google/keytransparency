// Copyright 2016 Google Inc. All Rights Reserved.
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

// Package mutation implements the monitor service. This package contains the
// core functionality.
package sequencer

import (
	"sync"
	"testing"
	"time"

	"github.com/google/trillian/util"

	tpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
)

var (
	minDurationS = time.Second * 1
	maxDurationH = time.Hour * 6
	minInMax     = int(maxDurationH / minDurationS)
	fakeNow      = parseTime("2015-10-21T04:29:00+00:00")
	oneOff       = parseTime("2015-10-21T03:29:00+00:00")
	twoOff       = parseTime("2015-10-21T02:29:00+00:00")
	threeOff     = parseTime("2015-10-21T01:29:00+00:00")
	sixOff       = parseTime("2015-10-20T22:29:00+00:00")
)

func TestEpochCreation(t *testing.T) {
	clock := util.NewFakeTimeSource(fakeNow)
	now := clock.Now()
	for _, tc := range []struct {
		wantForced int
		fakeNow    time.Time
		lastForced time.Time
		nTicks     int
		min        time.Duration
		max        time.Duration
	}{
		// Fresh start (last successful epoch not yet created):
		{0, now, now, 1, minDurationS, maxDurationH},
		{0, now, now, 2, minDurationS, maxDurationH},
		{0, now, now, minInMax - 3, minDurationS, maxDurationH},
		{1, now, now, minInMax, minDurationS, maxDurationH},
		{2, now, now, minInMax * 2, minDurationS, maxDurationH},
		{3, now, now, minInMax*3 + int(minInMax/2), minDurationS, maxDurationH},
		{3, now, now, minInMax*4 - int(minInMax/2), minDurationS, maxDurationH},
		{4, now, now, minInMax*4 + 10, minDurationS, maxDurationH},
		{4, now, now, minInMax*4 + int(minInMax*3/4), minDurationS, maxDurationH},
		{5, now, now, minInMax*5 + int(minInMax*3/4), minDurationS, maxDurationH},
		{6, now, now, minInMax*6 + int(minInMax/4), minDurationS, maxDurationH},
		// Resume from last epoch in the past:
		{1, now, oneOff, minInMax, minDurationS, maxDurationH},
		{1, now, sixOff, minInMax / 2, minDurationS, maxDurationH},
		{1, now, threeOff, minInMax, minDurationS, maxDurationH},
		// one forced epoch after 1 hour and one after 7 hours:
		{2, now, threeOff, minInMax + int(minInMax/2), minDurationS, maxDurationH},
		// One forced epoch "after 4 = -2+6 hours" catching up and 3 forced epochs
		// "after 10, 16, and 22 hours"
		{4, now, twoOff, minInMax * 4, minDurationS, maxDurationH},
	} {
		enforce := genEpochTicks(clock, tc.lastForced, genFakeTicker(now, tc.min, tc.nTicks), tc.min, tc.max)
		forcedTicks := 0
		for i := 0; i < tc.nTicks; i++ {
			force := <-enforce
			if force {
				forcedTicks++
			}
		}

		// Make sure we got the expected number of enforced epochs:
		if got, want := forcedTicks, tc.wantForced; got != want {
			t.Fatalf("Read from genEpochTicks(%v, %v, _, %v, %v) %v times: %v, want  %v",
				tc.fakeNow, tc.lastForced, tc.min, tc.max, tc.nTicks, got, tc.wantForced)
		}
	}
}

func TestRegisterMutationsChannel(t *testing.T) {
	seq := &Sequencer{
		mMux: &sync.Mutex{},
	}
	if got, want := len(seq.mChannels), 0; got != want {
		t.Errorf("Before adding channels, len(seq.mChannels)=%v, want %v", got, want)
	}

	// Adding some channels.
	numOfChannels := 5
	for i := 0; i < numOfChannels; i++ {
		ch := make(chan *tpb.GetMutationsResponse, 1)
		seq.RegisterMutationsChannel(ch)
	}
	if got, want := len(seq.mChannels), numOfChannels; got != want {
		t.Errorf("After adding channels, len(seq.mChannels)=%v, want %v", got, want)
	}
}

func TestDisseminateMutations(t *testing.T) {
	seq := &Sequencer{
		mMux: &sync.Mutex{},
	}

	numOfChannels := 3
	mChannels := make([]chan *tpb.GetMutationsResponse, numOfChannels)
	for i := 0; i < numOfChannels; i++ {
		mChannels[i] = make(chan *tpb.GetMutationsResponse, 1)
		seq.RegisterMutationsChannel(mChannels[i])
	}

	var wg sync.WaitGroup
	wg.Add(numOfChannels)

	// Read from the channels
	for _, ch := range mChannels {
		go func(ch chan *tpb.GetMutationsResponse) {
			<-ch
			wg.Done()
		}(ch)
	}

	// Write to the channels
	seq.disseminateMutations(&tpb.GetMutationsResponse{})

	wg.Wait()
}

// genFakeTicker creates a time.Tick and generates n Ticks starting from start.
func genFakeTicker(start time.Time, minInterval time.Duration, n int) <-chan time.Time {
	tc := make(chan time.Time, n)
	last := start
	for i := 0; i < n; i++ {
		last = last.Add(minInterval)
		tc <- last
	}
	return tc
}

// parseTime creates a time.Time from a time.RFC3339 formatted string.
func parseTime(ts string) time.Time {
	ti, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		panic("parseTime(_) expects time.RFC3339 formatted time strings as argument, got: " + ts)
	}
	return ti
}
