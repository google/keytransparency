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
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"

	tpb "github.com/google/key-transparency/core/proto/kt_types_v1"
)

var (
	data       string
	retryCount int
	retryDelay time.Duration
)

// postCmd represents the post command
var postCmd = &cobra.Command{
	Use:   "post [user email] -d {profile}",
	Short: "Update the account with the given profile",
	Long: `Post replaces the current key-set with the provided key-set, 
and verifies that both the previous and current key-sets are accurate. eg:

./key-transparency-client post foobar@example.com -d '{"app1": "dGVzdA==", "app2": "dGVzdA=="}'

User email MUST match the OAuth account used to authorize the update.
`,

	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate input.
		if len(args) < 1 {
			return fmt.Errorf("user email needs to be provided")
		}
		if data == "" {
			return fmt.Errorf("no profile provided")
		}
		if !viper.IsSet("client-secret") {
			return fmt.Errorf("no client secret provided")
		}
		var profile tpb.Profile
		if err := json.Unmarshal([]byte(data), &profile.Keys); err != nil {
			return fmt.Errorf("could not unmarshal profile: %v", err)
		}
		userID := args[0]
		timeout := viper.GetDuration("timeout")

		// Create client.
		c, err := GetClient(viper.GetString("client-secret"))
		if err != nil {
			return fmt.Errorf("error connecting: %v", err)
		}
		ctx, _ := context.WithTimeout(context.Background(), timeout)
		c.RetryCount = retryCount
		c.RetryDelay = retryDelay

		// Update.
		if _, err := c.Update(ctx, userID, &profile); err != nil {
			return fmt.Errorf("update failed: %v", err)
		}
		fmt.Printf("New Profile for %v: %+v", userID, profile)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(postCmd)

	postCmd.PersistentFlags().StringP("secret", "s", "", "Path to client secret json")
	if err := viper.BindPFlag("client-secret", postCmd.PersistentFlags().Lookup("secret")); err != nil {
		log.Fatalf("%v", err)
	}

	postCmd.PersistentFlags().StringVarP(&data, "data", "d", "", "JSON profile")
	postCmd.PersistentFlags().IntVar(&retryCount, "retries", 3, "Number of times to retry the update before failing")
	postCmd.PersistentFlags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Time to wait before retries. Set to server's signing period.")
}
