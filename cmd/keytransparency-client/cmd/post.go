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
	"encoding/base64"
	"fmt"
	"log"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	tpb "github.com/google/keytransparency/core/api/type/type_proto"
)

var (
	data       string
	retryCount int
	retryDelay time.Duration
)

// postCmd represents the post command
var postCmd = &cobra.Command{
	Use:   "post [user email] [app] -d {base64 key data}",
	Short: "Update the account with the given profile",
	Long: `Post replaces the current key-set with the provided key-set, 
and verifies that both the previous and current key-sets are accurate. eg:

./keytransparency-client post foobar@example.com app1 -d "dGVzdA=="

User email MUST match the OAuth account used to authorize the update.
`,

	PreRun: func(cmd *cobra.Command, args []string) {
		if err := readKeyStoreFile(); err != nil {
			log.Fatal(err)
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate input.
		if len(args) < 2 {
			return fmt.Errorf("user email and app-id need to be provided")
		}
		if data == "" {
			return fmt.Errorf("no key data provided")
		}
		if !viper.IsSet("client-secret") {
			return fmt.Errorf("no client secret provided")
		}
		profileData, err := base64.StdEncoding.DecodeString(data)
		if err != nil {
			return fmt.Errorf("hex.Decode(%v): %v", data, err)
		}
		userID := args[0]
		appID := args[1]
		timeout := viper.GetDuration("timeout")

		// Create client.
		c, err := GetClient(true)
		if err != nil {
			return fmt.Errorf("error connecting: %v", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		c.RetryCount = retryCount
		c.RetryDelay = retryDelay

		// Update.
		signers := store.Signers()
		authorizedKeys, err := store.PublicKeys()
		if err != nil {
			return fmt.Errorf("store.PublicKeys() failed: %v", err)
		}
		if err != nil {
			return fmt.Errorf("updateKeys() failed: %v", err)
		}
		// TODO: fill signers and authorizedKeys.
		u := &tpb.User{
			DomainId:       viper.GetString("domain"),
			AppId:          appID,
			UserId:         userID,
			PublicKeyData:  profileData,
			AuthorizedKeys: authorizedKeys,
		}
		if _, err := c.Update(ctx, u, signers); err != nil {
			return fmt.Errorf("update failed: %v", err)
		}
		fmt.Printf("New key for %v: %x\n", userID, data)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(postCmd)

	postCmd.PersistentFlags().StringP("secret", "s", "", "Path to client secret json")
	if err := viper.BindPFlag("client-secret", postCmd.PersistentFlags().Lookup("secret")); err != nil {
		log.Fatalf("%v", err)
	}

	postCmd.PersistentFlags().StringVarP(&data, "data", "d", "", "hex encoded key data")
	postCmd.PersistentFlags().IntVar(&retryCount, "retries", 3, "Number of times to retry the update before failing")
	postCmd.PersistentFlags().DurationVar(&retryDelay, "retry-delay", 5*time.Second, "Time to wait before retries. Set to server's signing period.")
}
