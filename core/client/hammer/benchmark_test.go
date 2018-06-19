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

package hammer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

func TestGenerateReport(t *testing.T) {
	ctx := context.Background()
	optTime := cmp.Comparer(func(x, y time.Duration) bool {
		// If x is > 0, y should also be > 0.
		return (x > 0 && y > 0) || (x == 0 && y == 0)
	})
	optFloat := cmp.Comparer(func(x, y float64) bool {
		// If x is > 0, y should also be > 0.
		return (x > 0 && y > 0) || (x == 0 && y == 0)
	})
	for _, tc := range []struct {
		desc     string
		reqCount int64
		ret      error
		workers  int
		want     *Stats
	}{
		{
			desc:     "1 op",
			reqCount: 1,
			workers:  1,
			want: &Stats{
				RequestCount: 1,
				AvgTotal:     500 * time.Nanosecond,
				Total:        500 * time.Nanosecond,
				Fastest:      500 * time.Nanosecond,
				Slowest:      500 * time.Nanosecond,
				Average:      500 * time.Nanosecond,
				QPS:          500,
				ErrorDist:    map[string]int{},
			},
		},
		{
			desc:     "multithread",
			reqCount: 100,
			workers:  10,
			want: &Stats{
				RequestCount: 100,
				AvgTotal:     500 * time.Nanosecond,
				Total:        500 * time.Nanosecond,
				Fastest:      500 * time.Nanosecond,
				Slowest:      500 * time.Nanosecond,
				Average:      500 * time.Nanosecond,
				QPS:          500,
				ErrorDist:    map[string]int{},
			},
		},
		{
			desc:     "all errors",
			reqCount: 10,
			workers:  10,
			ret:      errors.New("fake err"),
			want: &Stats{
				Total: 500 * time.Nanosecond,
				ErrorDist: map[string]int{
					"fake err": 10,
				},
			},
		},
	} {
		t.Run(tc.desc, func(t *testing.T) {
			reqs := make(chan request)
			go func() {
				for i := int64(0); i < tc.reqCount; i++ {
					reqs <- request{}
				}
				close(reqs)
			}()
			handlers := make([]ReqHandler, tc.workers)
			for i := range handlers {
				handlers[i] = func(context.Context, *request) error { return tc.ret }
			}

			stats := generateReport(ctx, reqs, handlers)
			if diff := cmp.Diff(stats, tc.want, optTime, optFloat); diff != "" {
				t.Errorf("generateReport(): diff: (-got +want)\n%v", diff)
			}
		})
	}
}
