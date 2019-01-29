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

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// getCmd represents the get command
var getCmd = &cobra.Command{
	Use:   "get [user email]",
	Short: "Retrieve and verify the current keyset",
	Long: `Retrieve the user profile from the key server and verify that the
results are consistent.`,
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
		profile, _, err := c.GetUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("failed to get user: %v", err)
		}
		fmt.Printf("Profile for %v: %+v\n", userID, profile)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(getCmd)
}
