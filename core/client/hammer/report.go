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
	"log"
	"sort"
	"time"
)

// Result represents the output of one operation.
type Result struct {
	Err        error
	Start, End time.Time
}

// Stats hold statistics on the output of many operations.
type Stats struct {
	requestCount int64
	avgTotal     time.Duration // Sum of individual latencies.
	total        time.Duration // Total wall time.
	fastest      time.Duration
	slowest      time.Duration
	average      time.Duration // Sum of latencies / count
	qps          float64       // Wall time / count
	errorDist    map[string]int
}

func collectStats(results <-chan Result) *Stats {
	var s Stats
	st := time.Now()
	for res := range results {
		if res.Err != nil {
			s.errorDist[res.Err.Error()]++
			continue
		}

		s.requestCount++
		l := res.End.Sub(res.Start)
		s.avgTotal += l
		if l < s.fastest {
			s.fastest = l
		}
		if l > s.slowest {
			s.slowest = l
		}
	}
	s.total = time.Since(st)
	s.qps = float64(s.requestCount) / s.total.Seconds()
	s.average = s.avgTotal / time.Duration(s.requestCount)
	return &s
}

// Print outputs the current stats to the console.
func (s *Stats) Print() {
	log.Printf("Hammer statistics:")
	log.Printf("Total Requests:  %v", s.requestCount)
	log.Printf("Average Latency: %v", s.average)
	log.Printf("Fastest Latency: %v", s.fastest)
	log.Printf("Slowest Latency: %v", s.slowest)
	log.Printf("Total QPS:       %v", s.qps)
	log.Printf("Errors:")

	// Sort errors by count
	type ErrCount struct {
		Error string
		Count int
	}
	errCounts := make([]ErrCount, 0, len(s.errorDist))
	for err, cnt := range s.errorDist {
		errCounts = append(errCounts, ErrCount{Error: err, Count: cnt})
	}
	sort.Slice(errCounts, func(i, j int) bool { return errCounts[i].Count > errCounts[j].Count })
	for _, errCount := range errCounts {
		log.Printf("  %v\t:%v", errCount.Count, errCount.Error)
	}
}
