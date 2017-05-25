package signer

import (
	"testing"
	"context"
	"time"
)

func TestCreateEpochNoMutations(t *testing.T) {
	// TODO should this (below) go here or into some "integration" package?
	// 1) no mutations added CreateEpoch called with alwaysCreateNewEpoch == true
	// expect new sth/epoch to be created
	// 2) no mutations added and CreateEpoch called with alwaysCreateNewEpoch == false
	// expect no epoch to be created
}


func TestEpochs(t *testing.T) {

	// check for mutations every ms:
	min := time.Millisecond
	max := 10
	tc := time.NewTicker(min)

	fakeCreateEpoch := func(ctx context.Context, enforce bool) error {
		// count changes
		return nil
	}
	// every 10 ms: create a new epoch (independent from mutations)
	go processEpochs(context.Context{}, tc, max, fakeCreateEpoch)

	select {
	case <- time.After(min*max*2):
		tc.Stop()
	}
}