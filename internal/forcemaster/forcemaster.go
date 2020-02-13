// Copyright 2020 Google Inc. All Rights Reserved.
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

package forcemaster

import (
	"context"
	"sync"

	"github.com/google/trillian/util/election2"
)

// Election is a stub Election that always believes to be the master.
type Election struct {
	id      string
	cancels []context.CancelFunc
	mu      sync.Mutex
}

func NewElection(id string) *Election {
	return &Election{
		id:      id,
		cancels: make([]context.CancelFunc, 0, 1),
	}
}

// Await returns immediately, as the instance is always the master.
func (ne *Election) Await(ctx context.Context) error {
	return nil
}

// WithMastership returns a cancelable context derived from the passed in context.
func (ne *Election) WithMastership(ctx context.Context) (context.Context, error) {
	cctx, done := context.WithCancel(ctx)
	ne.mu.Lock()
	defer ne.mu.Unlock()
	ne.cancels = append(ne.cancels, done)
	return cctx, nil
}

// Resign cancels the contexts obtained through WithMastership.
func (ne *Election) Resign(ctx context.Context) error {
	ne.mu.Lock()
	defer ne.mu.Unlock()
	for _, cancel := range ne.cancels {
		cancel()
	}
	ne.cancels = ne.cancels[:0] // Empty the slice but keep the memory.
	return nil
}

// Close does nothing because Election is always the master.
func (ne *Election) Close(ctx context.Context) error {
	return ne.Resign(ctx)
}

// Factory creates Election instances.
type Factory struct{}

// NewElection creates a specific Election instance.
func (nf Factory) NewElection(ctx context.Context, resourceID string) (election2.Election, error) {
	return NewElection(resourceID), nil
}
