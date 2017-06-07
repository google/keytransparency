package signer

import (
	"testing"
	"time"
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

type fakeClock struct {
	now time.Time
}

func (c fakeClock) Now() time.Time {
	return c.now
}

func (c fakeClock) Since(t time.Time) time.Duration {
	return c.now.Sub(t)
}

func TestEpochCreation(t *testing.T) {
	clock := fakeClock{now: fakeNow}
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
		got := 0
		for i := 0; i < tc.nTicks; i++ {
			force := <-enforce
			if force {
				got++
			}
		}

		// Make sure we got the expected number of enforced epochs:
		if got != tc.wantForced {
			t.Fatalf("Read from genEpochTicks(%v, %v, _, %v, %v) %v times: %v, want  %v",
				tc.fakeNow, tc.lastForced, tc.min, tc.max, tc.nTicks, got, tc.wantForced)
		}
	}
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
