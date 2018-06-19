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
	RequestCount int64
	AvgTotal     time.Duration // Sum of individual latencies.
	Total        time.Duration // Total wall time.
	Fastest      time.Duration
	Slowest      time.Duration
	Average      time.Duration // Sum of latencies / count
	QPS          float64       // Wall time / count
	ErrorDist    map[string]int
}

func collectStats(results <-chan Result) *Stats {
	s := &Stats{
		ErrorDist: make(map[string]int),
	}
	st := time.Now()
	for res := range results {
		if res.Err != nil {
			s.ErrorDist[res.Err.Error()]++
			continue
		}

		s.RequestCount++
		l := res.End.Sub(res.Start)
		s.AvgTotal += l
		s.Average = s.AvgTotal / time.Duration(s.RequestCount)
		if l < s.Fastest || s.Fastest == 0 {
			s.Fastest = l
		}
		if l > s.Slowest {
			s.Slowest = l
		}
	}
	s.Total = time.Since(st)
	s.QPS = float64(s.RequestCount) / s.Total.Seconds()
	return s
}

// Print outputs the current stats to the console.
func (s *Stats) Print() {
	log.Printf("Total Requests:  %v", s.RequestCount)
	log.Printf("Average Latency: %v", s.Average)
	log.Printf("Fastest Latency: %v", s.Fastest)
	log.Printf("Slowest Latency: %v", s.Slowest)
	log.Printf("Total QPS:       %v", s.QPS)
	log.Printf("Errors:          %v", len(s.ErrorDist))

	// Sort errors by count
	type ErrCount struct {
		Error string
		Count int
	}
	errCounts := make([]ErrCount, 0, len(s.ErrorDist))
	for err, cnt := range s.ErrorDist {
		errCounts = append(errCounts, ErrCount{Error: err, Count: cnt})
	}
	sort.Slice(errCounts, func(i, j int) bool { return errCounts[i].Count > errCounts[j].Count })
	for _, errCount := range errCounts {
		log.Printf("  %v\t:%v", errCount.Count, errCount.Error)
	}
}
