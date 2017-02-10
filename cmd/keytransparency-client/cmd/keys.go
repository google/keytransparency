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
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"text/tabwriter"
	"time"

	"github.com/google/keytransparency/core/crypto/keymaster"
	"github.com/google/keytransparency/core/signatures/p256"

	"github.com/golang/protobuf/ptypes"
	"github.com/spf13/cobra"

	kmpb "github.com/google/keytransparency/core/proto/keymaster"
)

const (
	keyStoreFile      = ".keystore"
	keyIDTruncatedLen = 8
)

var (
	pubKey      string
	privKey     string
	description string
	activate    bool
	keyType     string
	generate    bool
)

var store *keymaster.KeyMaster

// keysCmd represents the authorized-keys command.
var keysCmd = &cobra.Command{
	Use:   "authorized-keys",
	Short: "Manage authorized keys",
	Long: `Manage keys authorized to sign updates, and select the active signing key.

Verifying always happens using the keys listed in the previous epoch.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if err := readKeyStoreFile(); err != nil {
			log.Fatal(err)
		}
	},
	PersistentPostRunE: func(cmd *cobra.Command, args []string) error {
		buf, err := store.Marshal()
		if err != nil {
			return err
		}
		if err := ioutil.WriteFile(keyStoreFile, buf, 0600); err != nil {
			return err
		}
		return nil
	},
}

// addCmd represents the authorized-keys add command.
var addCmd = &cobra.Command{
	Use:   "add [ --privkey=[path] --activate | --pubkey=[path] | --generate --type=[key_type] --activate ] --description=[comment]",
	Short: "Add a key to the list of authorized keys",
	Long: `Provide a pair of public and private keys, already existing on disk, to be added to the list of authorized keys. The --generate flag can be used to generate a random key pair.

./keytransparency-client authorized-keys add --pubkey=/path/to/PEM/pubkey --description=[comment]
./keytransparency-client authorized-keys add --privkey=/path/to/PEM/privkey --activate --description=[comment]
./keytransparency-client authorized-keys add --generate --type=[key_type] --activate --description=[comment]
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate input.
		if generate {
			if pubKey != "" || privKey != "" {
				return fmt.Errorf("cannot provide public or private key with generate")
			}
			if keyType == "" {
				return fmt.Errorf("must provide key type")
			}
		} else {
			if pubKey == "" && privKey == "" {
				return fmt.Errorf("should provide private or public key")
			}
			if pubKey != "" && privKey != "" {
				return fmt.Errorf("cannot provide public and private key at the same time")
			}
		}

		// Add either a private key, or a public key.
		switch {
		case generate:
			switch keyType {
			case "ecdsa":
				skPEM, _, err := p256.GeneratePEMs()
				if err != nil {
					return err
				}
				if err := addPrivateKey(skPEM, description, activate); err == nil {
					return err
				}
			default:
				return fmt.Errorf("unrecognized key type %v", keyType)
			}
		case privKey != "":
			skPEM, err := ioutil.ReadFile(privKey)
			if err != nil {
				return err
			}
			if err := addPrivateKey(skPEM, description, activate); err == nil {
				return err
			}
		case pubKey != "":
			pkPEM, err := ioutil.ReadFile(pubKey)
			if err != nil {
				return err
			}
			if err := addPublicKey(pkPEM, description); err == nil {
				return err
			}
		}
		return nil
	},
}

// removeCmd represents the authorized-keys remove command.
var removeCmd = &cobra.Command{
	Use:   "remove [keyid]",
	Short: "Remove a key from the list of authorized keys",
	Long: `Remove a key based on its key ID from the list of authorized keys. e.g.:

./keytransparency-client authorized-keys remove [keyid]

If the list contains a single key, it cannot be removed.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate input.
		if len(args) < 1 {
			return fmt.Errorf("key ID needs to be provided")
		}

		// First remove verifying key with matching ID then attempt to
		// remove signing key if exist.
		keyID := keyID(args[0])
		if err := store.RemoveVerifyingKey(keyID); err != nil {
			return err
		}
		if err := store.RemoveSigningKey(keyID); err != nil && err != keymaster.ErrKeyNotExist {
			return err
		}
		return nil
	},
}

// activateCmd represents the authorized-keys activate command.
var activateCmd = &cobra.Command{
	Use:   "activate [keyid]",
	Short: "Activate a key in the list of authorized keys",
	Long: `Activate a key based on its key ID in the list of authorized keys. e.g.:

./keytransparency-client authorized-keys activate [keyid]
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Validate input.
		if len(args) < 1 {
			return fmt.Errorf("key ID needs to be provided")
		}
		keyID := keyID(args[0])
		if err := store.Activate(keyID); err != nil {
			return err
		}
		return nil
	},
}

// listCmd represents the authorized-keys list command.
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List all authorized keys",
	Long: `List metadata about all authorized keys. e.g.:

./keytransparency-client authorized-keys list

The actual keys are not listed, only their corresponding metadata.
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		signingInfo, verifyingInfo, err := store.Info()
		if err != nil {
			return err
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', tabwriter.Debug)

		// List signing keys.
		fmt.Fprintln(w, "Signing Keys:")
		fmt.Fprintln(w, "  ID\tAdded At\tStatus\tDescription")
		for _, info := range signingInfo {
			timestamp, err := ptypes.Timestamp(info.Metadata.AddedAt)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "  %v\t%v\t%v\t%v\n", info.Metadata.KeyId[:keyIDTruncatedLen], timestamp.Format(time.ANSIC), info.Status, info.Metadata.Description)
		}

		// List verifying keys.
		fmt.Fprintln(w, "\nVerifying Keys:")
		fmt.Fprintln(w, "  ID\tAdded At\tStatus\tDescription")
		for _, info := range verifyingInfo {
			timestamp, err := ptypes.Timestamp(info.Metadata.AddedAt)
			if err != nil {
				return err
			}
			fmt.Fprintf(w, "  %v\t%v\t%v\t%v\n", info.Metadata.KeyId[:keyIDTruncatedLen], timestamp.Format(time.ANSIC), info.Status, info.Metadata.Description)
		}

		if err := w.Flush(); err != nil {
			return nil
		}
		return nil
	},
}

func readKeyStoreFile() error {
	store = keymaster.New()
	// Authorized keys file might not exist.
	if _, err := os.Stat(keyStoreFile); err == nil {
		data, err := ioutil.ReadFile(keyStoreFile)
		if err != nil {
			return fmt.Errorf("reading keystore file failed: %v", err)
		}
		if err = keymaster.Unmarshal(data, store); err != nil {
			return fmt.Errorf("keystore.Unmarshak() failed: %v", err)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("error checking if keystore file exists: %v", err)
	}
	return nil
}

func addPublicKey(pkPEM []byte, description string) error {
	if activate {
		return errors.New("--activate requires a private key")
	}
	if _, err := store.AddVerifyingKey(description, pkPEM); err != nil {
		return err
	}
	return nil
}

func addPrivateKey(skPEM []byte, description string, activate bool) error {
	status := kmpb.SigningKey_INACTIVE
	if activate {
		status = kmpb.SigningKey_ACTIVE
	}
	keyID, err := store.AddSigningKey(status, description, skPEM)
	if err != nil {
		return err
	}

	// Add the corresponding verifying key.
	signer, err := store.Signer(keyID)
	if err != nil {
		return err
	}
	pkPEM, err := signer.PublicKeyPEM()
	if err != nil {
		return err
	}
	if _, err := store.AddVerifyingKey(description, pkPEM); err != nil {
		return err
	}
	return nil
}

func keyID(hint string) string {
	ids := store.KeyIDs()
	for _, id := range ids {
		if id[:len(hint)] == hint {
			return id
		}
	}
	return ""
}

func init() {
	RootCmd.AddCommand(keysCmd)
	keysCmd.AddCommand(addCmd)
	keysCmd.AddCommand(removeCmd)
	keysCmd.AddCommand(activateCmd)
	keysCmd.AddCommand(listCmd)

	addCmd.PersistentFlags().StringVar(&pubKey, "pubkey", "", "Path to a public key file")
	addCmd.PersistentFlags().StringVar(&privKey, "privkey", "", "Path to a private key file")
	addCmd.PersistentFlags().StringVar(&description, "description", "", "(Optional) Description of the added authorized key")
	addCmd.PersistentFlags().BoolVar(&activate, "activate", false, "(Optional) Activate the added signing key")
	addCmd.PersistentFlags().BoolVar(&generate, "generate", false, "Generate a random public and private key pair")
	addCmd.PersistentFlags().StringVar(&keyType, "type", "", "The key type to be generated, e.g., ecdsa")
}
