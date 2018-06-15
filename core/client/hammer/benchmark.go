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
	"sync"
	"time"
)

// ReqHandler executes a request.
type ReqHandler func(ctx context.Context, req *request) error

type request struct {
	UserIDs   []string
	BatchSize int
}

func startHandlers(ctx context.Context, inflightReqs <-chan request, reqHandlers []ReqHandler) <-chan Result {
	results := make(chan Result)

	go func() {
		var wg sync.WaitGroup
		for _, rh := range reqHandlers {
			wg.Add(1)
			go func(rh ReqHandler) {
				defer wg.Done()
				for req := range inflightReqs {
					st := time.Now()
					err := rh(ctx, &req)
					results <- Result{Err: err, Start: st, End: time.Now()}
				}
			}(rh)
		}
		wg.Wait()
		close(results)
	}()
	return results
}

func generateReport(ctx context.Context, reqs <-chan request, handlers []ReqHandler) {
	results := startHandlers(ctx, reqs, handlers)
	stats := collectStats(results)
	stats.Print()
}
