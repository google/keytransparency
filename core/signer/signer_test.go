package signer

import (
	"testing"
	"time"
	"golang.org/x/net/context"
)

func TestEpochCreation(t *testing.T) {

	min := time.Millisecond
	// expect an "enforced" epoch creation every x minEpochs
	x := 10
	max := time.Millisecond * time.Duration(x)
	N := 15
	tc := time.NewTicker(min)

	gotQ := make(chan bool, N)

	fakeCreateEpoch := func(ctx context.Context, enforce bool) error {
		if len(gotQ) < cap(gotQ) {
			gotQ <- enforce
		} else {
			tc.Stop()
			close(gotQ)
		}
		return nil
	}

	go processEpochs(context.TODO(), tc.C, max, fakeCreateEpoch)

	// expect one call with enforce == true; equivalent to one maxEpoch elapsed:
	got := 0
	want := 1
	for i := 0; i < N; i++ {
		force := <-gotQ
		if force {
			got++
			// expect the first x-1 calls with enforce == false (epoch creation not enforced)
			if i < (x - 1) {
				t.Errorf("Epoch enforced during minEpoch %d (before %dth epoch)", i, x)
			}
			if got > want {
				t.Errorf("More epochs created (%d) than expected (%d)", got, want)
			}
		}
	}

	// see if only one epoch creation was enforced:
	if got != want {
		t.Fatalf("Expected %v maxEpoch(s) but got %v", want, got)
	}
}