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
	"fmt"

	"github.com/spf13/cobra"
)

// cacheCmd represents the get command
var cacheCmd = &cobra.Command{
	Use:   "verify-cache",
	Short: "Verify inclusion promises from previous operations",
	Long: `Verify any cached certificate transparency signed certificate 
timestamps against the current CT signed tree head.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		c, err := GetClient("")
		if err != nil {
			return fmt.Errorf("Error creating client: %v", err)
		}
		errSCTs := c.CT.VerifySavedSCTs()
		if len(errSCTs) != 0 {
			return fmt.Errorf("Could not verify SCTs: %v", errSCTs)
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(cacheCmd)
}
