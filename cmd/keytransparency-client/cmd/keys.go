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
	"github.com/google/tink/go/insecure"
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

		keyset, err = tink.NewKeysetHandle(template)
		if err != nil {
			return err
		}

		return writeKeysetFile(keyset, keysetFile, masterPassword)
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
	PreRun: func(_ *cobra.Command, _ []string) {
		handle, err := readKeysetFile(keysetFile, masterPassword)
		if err != nil {
			log.Fatal(err)
		}
		keyset = handle
	},
	RunE: func(_ *cobra.Command, _ []string) error {
		keysetInfo, err := tink.GetKeysetInfo(keyset.Keyset())
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
func masterPBKDF(masterPassword string) (tink.AEAD, error) {
	if masterPassword == "" {
		return nil, fmt.Errorf("please provide a master password")
	}
	dk := pbkdf2.Key([]byte(masterPassword), salt,
		masterKeyIterations, masterKeyLen, masterKeyHashFunc)
	return aead.NewAESGCM(dk)
}

func encryptKeyset(keyset *tinkpb.Keyset, masterKey tink.AEAD) (*tinkpb.EncryptedKeyset, error) {
	serializedKeyset, err := proto.Marshal(keyset)
	if err != nil {
		return nil, fmt.Errorf("invalid keyset")
	}
	encrypted, err := masterKey.Encrypt(serializedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("encrypted failed: %s", err)
	}
	// get keyset info
	info, err := tink.GetKeysetInfo(keyset)
	if err != nil {
		return nil, fmt.Errorf("cannot get keyset info: %s", err)
	}
	encryptedKeyset := &tinkpb.EncryptedKeyset{
		EncryptedKeyset: encrypted,
		KeysetInfo:      info,
	}
	return encryptedKeyset, nil
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

	keyset, err := decryptKeyset(encryptedKeyset, masterKey)
	if err != nil {
		return nil, err
	}

	return insecure.KeysetHandle(keyset)
}

func decryptKeyset(encryptedKeyset *tinkpb.EncryptedKeyset, masterKey tink.AEAD) (*tinkpb.Keyset, error) {
	decrypted, err := masterKey.Decrypt(encryptedKeyset.EncryptedKeyset, []byte{})
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %s", err)
	}
	keyset := new(tinkpb.Keyset)
	if err := proto.Unmarshal(decrypted, keyset); err != nil {
		return nil, fmt.Errorf("invalid encrypted keyset")
	}
	return keyset, nil
}

func writeKeysetFile(keyset *tink.KeysetHandle, file, password string) error {
	masterKey, err := masterPBKDF(password)
	if err != nil {
		return err
	}
	encryptedKeyset, err := encryptKeyset(keyset.Keyset(), masterKey)
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
