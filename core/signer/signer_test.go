package signer

import (
	"testing"
	"time"
)

// no offset (last epoch was created now or does not exist yet)
const zero = 0 * time.Second

func TestEpochCreation(t *testing.T) {

	for _, tc := range []struct {
		want      int
		offset    time.Duration // last = time.Now() - offset
		min       time.Duration
		max       time.Duration
		stopAfter int
	}{
		// Fresh start (last successful epoch not yet created):
		{1, zero, time.Millisecond, time.Millisecond * 10, 15},
		{2, zero, time.Millisecond, time.Millisecond * 10, 22},
		{3, zero, time.Millisecond, time.Millisecond * 10, 33},
		{4, zero, time.Millisecond, time.Millisecond * 10, 42},
		{5, zero, time.Millisecond, time.Millisecond * 10, 51},
		// Resume from last epoch in the past (negative offset from time.Now()):
		{2, -9 * time.Millisecond, time.Millisecond, time.Millisecond * 10, 11},
		{2, -9 * time.Millisecond, time.Millisecond, time.Millisecond * 10, 11},
		{2, -99 * time.Millisecond, time.Millisecond, time.Millisecond * 100, 110},
		{2, -50 * time.Millisecond, time.Millisecond, time.Millisecond * 100, 155},
		{4, -99 * time.Millisecond, time.Millisecond, time.Millisecond * 100, 310},
	} {
		last := time.Now().Add(tc.offset)
		enforce := processEpochs(last, tc.min, tc.max)
		got := 0

		for i := 0; i < tc.stopAfter; i++ {
			force := <-enforce
			if force {
				got++
			}
			// Make sure we never exceed maxDuration:
			if time.Since(last) > tc.max {
				t.Fatalf("processEpochs(%v, %v, %v): %v elapsed since last enforced epoch, want <= %v",
					tc.offset, tc.min, tc.max, time.Since(last), tc.max)
			}
			last = time.Now()
		}

		// Make sure we got the expected number of enforced epochs:
		if got != tc.want {
			t.Fatalf("processEpochs(%v, %v, %v): %v, want  %v",
				tc.offset, tc.min, tc.max, tc.want, got)
		}
	}
}
