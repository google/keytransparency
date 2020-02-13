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

type mastership struct {
	e        election2.Election
	acquired time.Time
}

// Tracker tracks mastership of a collection of resources.
type Tracker struct {
	factory     election2.Factory
	maxHold     time.Duration
	master      map[string]mastership
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
		master:      make(map[string]mastership),
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
			if mt.setWatching(res) {
				go func() {
					defer mt.setNotWatching(res)
					if err := mt.watchResource(ctx, res); err != nil {
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
func (mt *Tracker) watchResource(ctx context.Context, res string) error {
	e, err := mt.factory.NewElection(ctx, res)
	if err != nil {
		return err
	}
	defer func() {
		if err := e.Close(ctx); err != nil {
			glog.Warningf("election.Close(%v): %v", res, err)
		}
	}()

	for err := error(nil); err == nil; err = ctx.Err() {
		if err := mt.watchOnce(ctx, e, res); err != nil {
			return err
		}
	}
	return nil
}

// watchOnce waits until it acquires mastership, marks itself as master for res,
// and then waits until either resign duration has passed or it loses
// mastership, at which point it marks itself as not master for res.  Returns
// an error if there were problems with acquiring mastership or resigning.
func (mt *Tracker) watchOnce(ctx context.Context, e election2.Election, res string) error {
	mt.setNotMaster(res)
	if err := e.Await(ctx); err != nil {
		return err
	}
	glog.Infof("Obtained mastership for %q", res)

	// Obtain mastership ctx *before* Masterships runs to avoid racing.
	mastershipCtx, err := e.WithMastership(ctx)
	if err != nil {
		return err
	}

	mt.setMaster(res, mastership{e: e, acquired: time.Now()})
	defer mt.setNotMaster(res)

	<-mastershipCtx.Done()
	// We don't know if we got here because we are no longer master or if
	// the parent context was closed. In either case work being done will
	// be canceled and we will mark ourselves as not-master until we can
	// acquire mastership again.
	glog.Warningf("No longer master for %q", res)
	return nil
}

// setWatching sets mt.watching[res] to true.
// Returns true if it set watching to true.
func (mt *Tracker) setWatching(res string) bool {
	mt.watchingMu.Lock()
	defer mt.watchingMu.Unlock()
	if !mt.watching[res] {
		mt.watching[res] = true
		return true
	}
	return false
}

func (mt *Tracker) setNotWatching(res string) {
	mt.watchingMu.Lock()
	defer mt.watchingMu.Unlock()
	delete(mt.watching, res)
}

func (mt *Tracker) setMaster(res string, m mastership) {
	isMaster.Set(1, res)
	mt.masterMu.Lock()
	defer mt.masterMu.Unlock()
	mt.master[res] = m
}

func (mt *Tracker) setNotMaster(res string) {
	isMaster.Set(0, res)
	mt.masterMu.Lock()
	defer mt.masterMu.Unlock()
	delete(mt.master, res)
}

// Masterships returns a map of resources to mastership contexts.
// Callers should cancel ctx when they no longer are actively using mastership.
// If Masterships is not called periodically, we may retain masterships for longer than maxHold.
func (mt *Tracker) Masterships(ctx context.Context) (map[string]context.Context, error) {
	mt.masterMu.RLock()
	defer mt.masterMu.RUnlock()
	mastershipCtx := make(map[string]context.Context)
	for res, m := range mt.master {
		// Resign mastership if we've held it for over maxHold.
		// Resign before attempting to acquire a mastership lock.
		if held := time.Since(m.acquired); held > mt.maxHold {
			glog.Infof("Resigning from %q after %v", res, held)
			if err := m.e.Resign(ctx); err != nil {
				glog.Errorf("Resign failed for resource %q: %v", res, err)
			}
			continue
		}

		cctx, err := m.e.WithMastership(ctx)
		if err != nil {
			return nil, err
		}
		mastershipCtx[res] = cctx
	}
	return mastershipCtx, nil
}
