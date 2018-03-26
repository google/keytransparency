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

	"github.com/google/trillian/types"
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
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) < 2 {
			return fmt.Errorf("user email and application need to be provided")
		}
		userID := args[0]
		appID := args[1]
		timeout := viper.GetDuration("timeout")
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		userCreds, err := userCreds(ctx, false)
		if err != nil {
			return err
		}
		c, err := GetClient(ctx, userCreds)
		if err != nil {
			return fmt.Errorf("Error connecting: %v", err)
		}
		if end == 0 {
			// Get the current epoch.
			slr, err := c.LatestSTH(ctx)
			if err != nil {
				return fmt.Errorf("GetEntry failed: %v", err)
			}
			revision, err := mapRevisionFor(slr)
			if err != nil {
				return err
			}
			if verbose {
				fmt.Printf("Got current epoch: %v\n", slr.TreeSize-1)
			}
			end = revision
		}

		profiles, err := c.ListHistory(ctx, userID, appID, start, end)
		if err != nil {
			return fmt.Errorf("ListHistory failed: %v", err)
		}

		// Sort map heads.
		keys := make([]*types.MapRootV1, 0, len(profiles))
		for k := range profiles {
			keys = append(keys, k)
		}
		sort.Sort(mapHeads(keys))
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)
		fmt.Fprintln(w, "Epoch\tTimestamp\tProfile")
		for _, m := range keys {
			t := time.Unix(0, int64(m.TimestampNanos))
			fmt.Fprintf(w, "%v\t%v\t%v\n", m.Revision, t.Format(time.UnixDate), profiles[m])
		}
		if err := w.Flush(); err != nil {
			return nil
		}
		return nil
	},
}

// mapRevisionFor returns the latest map revision, given the latest sth.
// The log is the authoritative source of the latest revision.
func mapRevisionFor(sth *types.LogRootV1) (int64, error) {
	treeSize := int64(sth.TreeSize)
	// TreeSize = max_index + 1 because the log starts at index 0.
	maxIndex := treeSize - 1

	// The revision of the map is its index in the log.
	if maxIndex < 0 {
		return 0, fmt.Errorf("log is uninitialized")
	}
	return maxIndex, nil
}

// mapHeads satisfies sort.Interface to allow sorting []MapHead by epoch.
type mapHeads []*types.MapRootV1

func (m mapHeads) Len() int           { return len(m) }
func (m mapHeads) Swap(i, j int)      { m[i], m[j] = m[j], m[i] }
func (m mapHeads) Less(i, j int) bool { return m[i].Revision < m[j].Revision }

func init() {
	RootCmd.AddCommand(histCmd)

	histCmd.PersistentFlags().Int64Var(&start, "start", 1, "Start epoch")
	histCmd.PersistentFlags().Int64Var(&end, "end", 0, "End epoch")
}
