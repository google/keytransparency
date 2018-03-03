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

package cmd

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/google/keytransparency/core/authentication"

	"github.com/aybabtme/uniplot/histogram"
	"github.com/paulbellamy/ratecounter"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"

	tm "github.com/buger/goterm"
	tpb "github.com/google/keytransparency/core/api/type/type_proto"
)

var (
	maxWorkers int
	workers    int
	memLog     = new(bytes.Buffer)
	ramp       time.Duration
)

func init() {
	log.SetOutput(memLog)

	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)

	RootCmd.AddCommand(hammerCmd)

	hammerCmd.Flags().IntVar(&maxWorkers, "workers", 1, "Number of parallel workers")
	hammerCmd.Flags().DurationVar(&ramp, "ramp", 1*time.Second, "Time to spend ramping up")
}

// hammerCmd represents the post command
var hammerCmd = &cobra.Command{
	Use:   "hammer",
	Short: "Loadtest the server",
	Long:  ``,

	PreRun: func(cmd *cobra.Command, args []string) {
		if err := readKeyStoreFile(); err != nil {
			log.Fatal(err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		parallel(ctx, maxWorkers)
		return nil
	},
}

func parallel(ctx context.Context, maxWorkers int) {
	times := make(chan time.Duration)
	jobs := make(chan job)
	var wg sync.WaitGroup
	go recordLatencies(ctx, times)
	go generateJobs(ctx, jobs)

	// Slowly add workers up to maxWorkers
	ramp := time.NewTicker(time.Duration(ramp.Nanoseconds() / int64(maxWorkers)))
	for ; workers < maxWorkers && ctx.Err() == nil; <-ramp.C {
		workers++
		wg.Add(1)
		go runJobsInThread(ctx, workers, jobs, times, &wg)
	}
	ramp.Stop()
	wg.Wait()
}

type job func() error

func generateJobs(ctx context.Context, jobs chan<- job) {
	i := 0
	for {
		select {
		case <-ctx.Done():
			return
		case jobs <- bindJob(ctx, i):
			i++
		}
	}
}

func bindJob(ctx context.Context, i int) func() error {
	userID := fmt.Sprintf("user_%v", i)
	return func() error {
		return writeOp(ctx, "app1", userID)
	}
}

func runJobsInThread(ctx context.Context, id int, jobs <-chan job, times chan<- time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case f := <-jobs:
			start := time.Now()
			if err := f(); err != nil {
				log.Printf("f(): %v", err)
				continue
			}
			times <- time.Since(start)
		}
	}
}

func recordLatencies(ctx context.Context, times <-chan time.Duration) {
	//start := time.Now()
	latencies := make([]float64, 0, 1000)
	refresh := time.NewTicker(250 * time.Millisecond)
	newworker := time.NewTicker(time.Duration(ramp.Nanoseconds() / int64(maxWorkers)))
	qps := ratecounter.NewRateCounter(5 * time.Second)

	qpsData := new(tm.DataTable)
	qpsData.AddColumn("Workers")
	qpsData.AddColumn("QPS")
	qpsData.AddRow(0, 0)

	for {
		select {
		case <-ctx.Done():
			return
		case t := <-times:
			latencies = append(latencies, t.Seconds())
			qps.Incr(1)
		case <-refresh.C:
			draw(latencies, qpsData, qps.Rate())
		case <-newworker.C:
			qpsData.AddRow(float64(workers), float64(qps.Rate()))
		}
	}
}

func draw(latencies []float64, data *tm.DataTable, qps int64) {
	tm.Clear()
	tm.MoveCursor(0, 0)

	// Global stats
	tm.Printf("Workers: %v\n", workers)
	tm.Printf("Total Requests: %v\n", len(latencies))
	tm.Printf("Recent QPS:    %v\n", qps)

	// Threads per QPS graph
	tm.Printf("QPS Chart:\n")
	chart := tm.NewLineChart(100, 20)
	tm.Println(chart.Draw(data))

	// Latency Hist
	tm.Printf("Latency Histogram:\n")
	width := 50
	height := 10

	hist := histogram.Hist(height, latencies)
	histogram.Fprint(tm.Output, hist, histogram.Linear(width))

	// Console output
	box := tm.NewBox(180, 10, 0)
	box.Write(memLog.Bytes())
	tm.Println(box)

	tm.Flush()
}

// writeOp performs one write command and returns the time it took to complete.
func writeOp(ctx context.Context, appID, userID string) error {
	timeout := viper.GetDuration("timeout")
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	userCreds := authentication.GetFakeCredential(userID)
	c, err := GetClient(ctx, userCreds)
	if err != nil {
		return fmt.Errorf("error connecting: %v", err)
	}

	// Update.
	signers := store.Signers()
	authorizedKeys, err := store.PublicKeys()
	if err != nil {
		return fmt.Errorf("store.PublicKeys() failed: %v", err)
	}
	if err != nil {
		return fmt.Errorf("updateKeys() failed: %v", err)
	}
	u := &tpb.User{
		DomainId:       viper.GetString("domain"),
		AppId:          appID,
		UserId:         userID,
		PublicKeyData:  []byte("publickey"),
		AuthorizedKeys: authorizedKeys,
	}
	if _, err := c.Update(ctx, u, signers); err != nil {
		return fmt.Errorf("update failed: %v", err)
	}
	return nil
}
