package signer

import (
	"testing"
	"time"
	"golang.org/x/net/context"
)

func TestEpochCreation(t *testing.T) {

	// TODO use table driven test
	// TODO https://github.com/golang/go/wiki/CodeReviewComments#useful-test-failures

	min := time.Millisecond
	// expect an "enforced" epoch creation every x minEpochs
	x := 10
	max := time.Millisecond * time.Duration(x)
	stopAfter := 22


	gotQ := make(chan bool, stopAfter)

	fakeCreateEpoch := func(ctx context.Context, enforce bool) error {
		if len(gotQ) < cap(gotQ) {
			gotQ <- enforce
		} else {
			close(gotQ)
		}
		return nil
	}

	last := time.Now()
	// FIXME this go-routine leaks (sometimes)
	quit := make(chan bool)
	go processEpochs(context.TODO(), last, min, max, fakeCreateEpoch, quit)

	// expect one call with enforce == true; equivalent to one maxEpoch elapsed:
	got := 0
	want := 2
	for i := 0; i < stopAfter; i++ {
		force := <-gotQ
		if force {
			got++
			// expect the first x-1 calls with enforce == false (epoch creation not enforced)
			if i < (x - 1) {
				//t.Errorf("Epoch enforced during minEpoch %d (before %dth epoch)", i, x)
			}
			if got > want {
				t.Errorf("Epochs enforced = %d; want %d", got, want)
			}
		}
	}
	quit<-true

	// see if only one epoch creation was enforced:
	if got != want {
		t.Fatalf("Expected %v maxEpoch(s) but got %v", want, got)
	}
}
