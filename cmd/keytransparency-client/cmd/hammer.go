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
	"time"

	"github.com/google/keytransparency/core/client/hammer"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
)

var (
	maxWorkers    int
	maxOperations int
)

func init() {
	// Silence "logging before flag.Parse"
	pflag.CommandLine.AddGoFlagSet(flag.CommandLine)
	flag.CommandLine.Parse([]string{})

	RootCmd.AddCommand(hammerCmd)

	hammerCmd.Flags().IntVar(&maxWorkers, "workers", 2000, "Number of parallel workers")
	hammerCmd.Flags().IntVar(&maxOperations, "operations", 10000, "Number of operations")
	hammerCmd.Flags().StringVarP(&masterPassword, "password", "p", "", "The master key to the local keyset")
}

// hammerCmd represents the post command
var hammerCmd = &cobra.Command{
	Use:   "hammer",
	Short: "Loadtest the server",
	Long:  `Sends update requests for user_1 through user_n using a select number of workers in parallel.`,

	PreRun: func(cmd *cobra.Command, args []string) {
		handle, err := readKeysetFile(keysetFile, masterPassword)
		if err != nil {
			log.Fatal(err)
		}
		keyset = handle
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		ktURL := viper.GetString("kt-url")
		domainID := viper.GetString("domain")
		timeout := viper.GetDuration("timeout")

		log.Printf("Hammering %v/domains/%v: with %v timeout", ktURL, domainID, timeout)

		ctx := context.Background()

		h, err := hammer.New(ctx, dial, callOptions,
			ktURL, domainID, timeout, keyset)
		if err != nil {
			return err
		}

		return h.Run(ctx, maxWorkers, hammer.Config{
			BatchWriteQPS:   1,
			BatchWriteSize:  1000,
			BatchWriteCount: 60,

			WriteQPS:   20,
			WriteCount: 1000,

			ReadQPS:   50,
			ReadCount: 1000,

			HistoryQPS:       1000,
			HistoryCount:     1000,
			HistoryBatchSize: 1000,

			Duration: 2 * time.Minute,
		})
	},
}

func callOptions(userID string) []grpc.CallOption {
	return []grpc.CallOption{
		grpc.PerRPCCredentials(authentication.GetFakeCredential(userID)),
	}
}
