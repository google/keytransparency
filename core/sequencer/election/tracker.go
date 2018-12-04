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

package election

import (
	"context"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/google/trillian/monitoring"
	"github.com/google/trillian/util/election2"
)

const resourceLabel = "resource"

var (
	once     sync.Once
	isMaster monitoring.Gauge
)

func createMetrics(mf monitoring.MetricFactory) {
	isMaster = mf.NewGauge(
		"is_master",
		"Set to 1 for resources for which this instance is currently master",
		resourceLabel)
}

// Tracker tracks mastership of a collection of resources.
type Tracker struct {
	factory     election2.Factory
	maxHold     time.Duration
	master      map[string]election2.Election
	masterMu    sync.RWMutex
	watching    map[string]bool
	watchingMu  sync.RWMutex
	newResource chan string
}

// NewTracker returns a new mastership tracker.
func NewTracker(factory election2.Factory, maxHold time.Duration, metricFactory monitoring.MetricFactory) *Tracker {
	once.Do(func() { createMetrics(metricFactory) })
	return &Tracker{
		factory:     factory,
		maxHold:     maxHold,
		master:      make(map[string]election2.Election),
		watching:    make(map[string]bool),
		newResource: make(chan string),
	}
}

// AddResource makes the mastership tracker aware of new resources.
// The same resource may be added an unlimited number of times.
func (mt *Tracker) AddResource(res string) {
	mt.newResource <- res
}

// Run starts new watchers for new resources.
func (mt *Tracker) Run(ctx context.Context) {
	for {
		select {
		case res := <-mt.newResource:
			if !mt.isWatching(res) {
				go func() {
					if err := mt.watchResource(ctx, res, mt.maxHold); err != nil {
						glog.Errorf("watchResource(%v): %v", res, err)
					}
				}()
			}
		case <-ctx.Done():
			glog.Infof("election: Run() exiting due to expired context: %v", ctx.Err())
			return
		}
	}
}

// watchResource is a blocking method that runs elections for res and updates mt.master.
func (mt *Tracker) watchResource(ctx context.Context, res string, resign time.Duration) error {
	e, err := mt.factory.NewElection(ctx, res)
	if err != nil {
		return err
	}
	mt.setWatching(res)
	defer func(ctx context.Context) {
		if err := e.Close(ctx); err != nil {
			glog.Warningf("election.Close(%v): %v", res, err)
		}
		mt.setNotWatching(res)
	}(ctx)

	for {
		if err := func() error {
			mt.setNotMaster(res)
			if err := e.Await(ctx); err != nil {
				return err
			}
			glog.Infof("Obtained mastership for %v", res)

			mt.setMaster(res, e)
			defer mt.setNotMaster(res)

			mastershipCtx, err := e.WithMastership(ctx)
			if err != nil {
				return err
			}

			select {
			case <-time.After(resign):
				glog.Infof("Resigning from %v after %v", res, resign)
				if err := e.Resign(ctx); err != nil {
					glog.Errorf("Resign(%v): %v", res, err)
				}
			case <-mastershipCtx.Done():
				glog.Warningf("No longer master for %v", res)
				// If the master ctx is canceled, exit for loop.
				if err := ctx.Err(); err != nil {
					return err
				}
				if err := e.Resign(ctx); err != nil {
					glog.Errorf("Resign(%v): %v", res, err)
				}
			}
			return nil
		}(); err != nil {
			return err
		}
	}
}

func (mt *Tracker) isWatching(res string) bool {
	mt.watchingMu.RLock()
	defer mt.watchingMu.RUnlock()
	return mt.watching[res]
}

func (mt *Tracker) setWatching(res string) {
	mt.watchingMu.Lock()
	defer mt.watchingMu.Unlock()
	mt.watching[res] = true
}

func (mt *Tracker) setNotWatching(res string) {
	mt.watchingMu.Lock()
	defer mt.watchingMu.Unlock()
	delete(mt.watching, res)
}

func (mt *Tracker) setMaster(res string, e election2.Election) {
	isMaster.Set(1, res)
	mt.masterMu.Lock()
	defer mt.masterMu.Unlock()
	mt.master[res] = e
}

func (mt *Tracker) setNotMaster(res string) {
	isMaster.Set(0, res)
	mt.masterMu.Lock()
	defer mt.masterMu.Unlock()
	delete(mt.master, res)
}

// Masterships returns a map of resources to mastership contexts.
func (mt *Tracker) Masterships(ctx context.Context) (map[string]context.Context, error) {
	mt.masterMu.RLock()
	defer mt.masterMu.RUnlock()
	mastershipCtx := make(map[string]context.Context)
	for res, e := range mt.master {
		cctx, err := e.WithMastership(ctx)
		if err != nil {
			return nil, err
		}
		mastershipCtx[res] = cctx
	}
	return mastershipCtx, nil
}
