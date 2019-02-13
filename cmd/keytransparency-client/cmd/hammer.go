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
	"context"
	"flag"
	"log"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/client/hammer"
	"github.com/google/keytransparency/core/crypto/tinkio"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/tink/go/keyset"
)

var (
	maxWorkers    int
	maxOperations int
	pageSize      int
	qps           int
	testTypes     string
	duration      time.Duration
)

func init() {
	// Silence "logging before flag.Parse"
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	_ = flag.CommandLine.Parse([]string{})

	RootCmd.AddCommand(hammerCmd)

	hammerCmd.Flags().DurationVar(&duration, "duration", 10*time.Minute, "Maximum time to run each test")
	hammerCmd.Flags().StringVar(&testTypes, "types", "batch,write,read,audit", "Types of stress tests to run, comma separated")
	hammerCmd.Flags().IntVar(&qps, "qps", 100, "Numer of requests a second")
	hammerCmd.Flags().IntVar(&pageSize, "batch", 10, "Number of entries to process at once")
	hammerCmd.Flags().IntVar(&maxWorkers, "workers", 1000, "Number of parallel workers. Best when workers = QPS * timeout")
	hammerCmd.Flags().IntVar(&maxOperations, "operations", 10000, "Number of operations")
	hammerCmd.Flags().StringVarP(&masterPassword, "password", "p", "", "The master key to the local keyset")
}

// hammerCmd represents the post command
var hammerCmd = &cobra.Command{
	Use:   "hammer",
	Short: "Loadtest the server",
	Long:  `Sends update requests for user_1 through user_n using a select number of workers in parallel.`,

	RunE: func(_ *cobra.Command, _ []string) error {
		ktURL := viper.GetString("kt-url")
		directoryID := viper.GetString("directory")
		timeout := viper.GetDuration("timeout")

		masterKey, err := tinkio.MasterPBKDF(masterPassword)
		if err != nil {
			log.Fatal(err)
		}
		handle, err := keyset.Read(
			&tinkio.ProtoKeysetFile{File: keysetFile},
			masterKey)
		if err != nil {
			log.Fatal(err)
		}

		log.Printf("Hammering %v/directories/%v: with %v timeout", ktURL, directoryID, timeout)

		ctx := context.Background()

		h, err := hammer.New(ctx, dial, callOptions,
			ktURL, directoryID, timeout, handle)
		if err != nil {
			return err
		}

		types := make(map[string]bool)
		for _, s := range strings.Split(testTypes, ",") {
			types[s] = true
		}

		return h.Run(ctx, maxWorkers, hammer.Config{
			TestTypes: types,

			BatchWriteQPS:   qps,
			BatchWriteSize:  pageSize,
			BatchWriteCount: maxOperations,

			WriteQPS:   qps,
			WriteCount: maxOperations,

			ReadQPS:      qps,
			ReadCount:    maxOperations,
			ReadPageSize: 1,

			HistoryQPS:      qps,
			HistoryCount:    maxOperations,
			HistoryPageSize: pageSize,

			Duration: duration,
		})
	},
}

func callOptions(userID string) []grpc.CallOption {
	return []grpc.CallOption{
		grpc.PerRPCCredentials(authentication.GetFakeCredential(userID)),
	}
}
