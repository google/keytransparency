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
	"log"

	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/signature"
	"github.com/spf13/cobra"

	"github.com/google/keytransparency/core/crypto/tinkio"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const keysetFile = ".keyset"

var (
	keyType        string
	masterPassword string
)

// keysCmd represents the authorized-keys command.
var keysCmd = &cobra.Command{
	Use:   "authorized-keys",
	Short: "Manage authorized keys",
	Long: `Manage the authorized-keys list with tinkey
	https://github.com/google/tink/blob/master/doc/TINKEY.md`,
}

// createCmd creates a new keyset
var createCmd = &cobra.Command{
	Use:   "create-keyset",
	Short: "Creates a new keyset",
	Long: `Creates a new keyset and generates the first key:

./keytransparency-client authorized-keys create-keyset
`,
	RunE: func(_ *cobra.Command, _ []string) error {
		template, err := keyTemplate(keyType)
		if err != nil {
			return err
		}

		handle, err := keyset.NewHandle(template)
		if err != nil {
			return err
		}
		masterKey, err := tinkio.MasterPBKDF(masterPassword)
		if err != nil {
			return err
		}

		return handle.Write(&tinkio.ProtoKeysetFile{File: keysetFile}, masterKey)
	},
}

func keyTemplate(keyType string) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case "P256":
		return signature.ECDSAP256KeyTemplate(), nil
	case "P384":
		return signature.ECDSAP384KeyTemplate(), nil
	case "P521":
		return signature.ECDSAP521KeyTemplate(), nil
	default:
		return nil, fmt.Errorf("unknown key-type: %s", keyType)
	}
}

// listCmd represents the authorized-keys list command.
var listCmd = &cobra.Command{
	Use:   "list-keyset",
	Short: "List all authorized keys",
	Long: `List metadata about all authorized keys. e.g.:

./keytransparency-client authorized-keys list-keyset

The actual keys are not listed, only their corresponding metadata.
`,
	Run: func(_ *cobra.Command, _ []string) {
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
		// List signing keys.
		fmt.Printf("My Authorized Keys:\n%v\n", handle.String())
	},
}

func init() {
	RootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(listCmd)
	keysCmd.AddCommand(createCmd)

	keysCmd.PersistentFlags().StringVarP(&masterPassword, "password", "p", "", "The master key to the local keyset")

	createCmd.Flags().StringVar(&keyType, "key-type", "P256", "Type of keys to generate: [P256, P384, P521]")
}
