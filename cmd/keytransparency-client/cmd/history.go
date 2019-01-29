// Copyright 2016 Google Inc. All Rights Reserved.
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
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	start, end int64
)

// histCmd fetches the account history for a user
var histCmd = &cobra.Command{
	Use:   "history [user email] [app]",
	Short: "Retrieve and verify all keys used for this account",
	Long: `Retrieve all user profiles for this account from the key server
and verify that the results are consistent.`,
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("user email needs to be provided")
		}
		userID := args[0]
		timeout := viper.GetDuration("timeout")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		c, err := GetClient(ctx)
		if err != nil {
			return fmt.Errorf("error connecting: %v", err)
		}
		if end == 0 {
			// Get the current revision.
			slr, smr, err := c.VerifiedGetLatestRevision(ctx)
			if err != nil {
				return fmt.Errorf("failed to get user: %v", err)
			}
			if verbose {
				fmt.Printf("Got current revision: %v\n", slr.TreeSize-1)
			}
			end = int64(smr.Revision)
		}

		roots, profiles, err := c.PaginateHistory(ctx, userID, start, end)
		if err != nil {
			return fmt.Errorf("failed fetching history: %v", err)
		}
		compressed, err := client.CompressHistory(profiles)
		if err != nil {
			return fmt.Errorf("failed compressing history: %v", err)
		}

		// Sort map heads.
		keys := make(uint64Slice, 0, len(compressed))
		for k := range compressed {
			keys = append(keys, k)
		}
		sort.Sort(keys)
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
		fmt.Fprintln(w, "Revision\tTimestamp\tProfile")
		for _, e := range keys {
			mapRoot := roots[e]
			t := time.Unix(0, int64(mapRoot.TimestampNanos))
			data := compressed[e]
			fmt.Fprintf(w, "%v\t%v\t%v\n", mapRoot.Revision, t.Format(time.UnixDate), data)
		}
		if err := w.Flush(); err != nil {
			return nil
		}
		return nil
	},
}

// uint64Slice satisfies sort.Interface.
type uint64Slice []uint64

func (m uint64Slice) Len() int           { return len(m) }
func (m uint64Slice) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m uint64Slice) Less(i, j int) bool { return m[i] < m[j] }

func init() {
	RootCmd.AddCommand(histCmd)

	histCmd.PersistentFlags().Int64Var(&start, "start", 1, "Start revision")
	histCmd.PersistentFlags().Int64Var(&end, "end", 0, "End revision")
}
