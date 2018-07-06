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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"text/tabwriter"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/aead"
	"github.com/google/tink/go/tink"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/pbkdf2"

	tinkpb "github.com/google/tink/proto/tink_go_proto"
)

const (
	keysetFile          = ".keyset"
	masterKeyLen        = 32
	masterKeyIterations = 4096
)

var (
	// openssl rand -hex 32
	salt, _           = hex.DecodeString("00afc05d5b131a1dfd140a146b87f2f07826a8d4576cb4feef43f80f0c9b1c2f")
	masterKeyHashFunc = sha256.New
	keyType           string
	masterPassword    string
)

var keyset *tink.KeysetHandle

// keysCmd represents the authorized-keys command.
var keysCmd = &cobra.Command{
	Use:   "authorized-keys",
	Short: "Manage authorized keys",
	Long: `Manage the authorized-keys list with tinkey
	https://github.com/google/tink/blob/master/doc/TINKEY.md`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		_, err := signature.RegisterStandardKeyTypes()
		return err
	},
}

// createCmd creates a new keyset
var createCmd = &cobra.Command{
	Use:   "create-keyset",
	Short: "Creates a new keyset",
	Long: `Creates a new keyset and generates the first key:

./keytransparency-client authorized-keys create-keyset
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		template, err := keyTemplate(keyType)
		if err != nil {
			return err
		}

		keyset, err = tink.CleartextKeysetHandle().GenerateNew(template)
		if err != nil {
			return err
		}

		return writeKeysetFile(keyset, keysetFile, masterPassword)
	},
}

func keyTemplate(keyType string) (*tinkpb.KeyTemplate, error) {
	switch keyType {
	case "P256":
		return signature.EcdsaP256KeyTemplate(), nil
	case "P384":
		return signature.EcdsaP384KeyTemplate(), nil
	case "P521":
		return signature.EcdsaP521KeyTemplate(), nil
	default:
		return nil, fmt.Errorf("Unknown key-type: %s", keyType)
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
	PreRun: func(cmd *cobra.Command, args []string) {
		handle, err := readKeysetFile(keysetFile, masterPassword)
		if err != nil {
			log.Fatal(err)
		}
		keyset = handle
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		keysetInfo, err := keyset.KeysetInfo()
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)

		// List signing keys.
		fmt.Fprintln(w, "My Keys:")
		fmt.Fprintln(w, "  ID\tStatus\tType")
		for _, info := range keysetInfo.GetKeyInfo() {
			fmt.Fprintf(w, "  %v\t%v\t%v\t\n", info.KeyId, info.Status, info.TypeUrl)
		}

		// Tink keysets do not currently support adding public keys without also having the private key.
		fmt.Fprintln(w, "\nOther Authorized Keys: none")

		if err := w.Flush(); err != nil {
			return nil
		}
		return nil
	},
}

// masterPBKDF converts the master password into the master key.
func masterPBKDF(masterPassword string) (tink.Aead, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("please provide a master password")
	}
	dk := pbkdf2.Key([]byte(masterPassword), salt,
		masterKeyIterations, masterKeyLen, masterKeyHashFunc)
	return aead.NewAesGcm(dk)
}

func readKeysetFile(file, password string) (*tink.KeysetHandle, error) {
	masterKey, err := masterPBKDF(password)
	if err != nil {
		return nil, err
	}
	data, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file %q failed: %v", file, err)
	}

	encryptedKeyset := new(tinkpb.EncryptedKeyset)
	if err := proto.Unmarshal(data, encryptedKeyset); err != nil {
		return nil, fmt.Errorf("could not parse encrypted keyset: %v", err)
	}

	keyset, err := tink.DecryptKeyset(encryptedKeyset, masterKey)
	if err != nil {
		return nil, err
	}

	return tink.CleartextKeysetHandle().ParseKeyset(keyset)
}

func writeKeysetFile(keyset *tink.KeysetHandle, file, password string) error {
	masterKey, err := masterPBKDF(password)
	if err != nil {
		return err
	}
	encryptedKeyset, err := tink.EncryptKeyset(keyset.Keyset(), masterKey)
	if err != nil {
		return err
	}
	serialized, err := proto.Marshal(encryptedKeyset)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(file, serialized, 0600)
}

func init() {
	RootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(listCmd)
	keysCmd.AddCommand(createCmd)

	keysCmd.PersistentFlags().StringVarP(&masterPassword, "password", "p", "", "The master key to the local keyset")

	createCmd.Flags().StringVar(&keyType, "key-type", "P256", "Type of keys to generate: [P256, P384, P521]")
}
