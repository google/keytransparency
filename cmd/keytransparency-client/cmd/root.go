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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/client/verifier"
	"github.com/google/keytransparency/impl/authentication"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
)

var (
	cfgFile string
	verbose bool
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "keytransparency-client",
	Short: "A client for interacting with the key transparency server",
	Long: `The key transparency client retrieves and sets keys in the
key transparency server.  The client verifies all cryptographic proofs the
server provides to ensure that account data is accurate.`,
	PersistentPreRun: func(_ *cobra.Command, _ []string) {
		if verbose {
			client.Vlog = log.New(os.Stdout, "", log.LstdFlags)
		}
	},
	SilenceUsage: true,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.keytransparency.yaml)")

	RootCmd.PersistentFlags().String("directory", "default", "Directory within the KT server")
	RootCmd.PersistentFlags().String("kt-url", "sandbox.keytransparency.dev:443", "URL of Key Transparency server")
	RootCmd.PersistentFlags().String("kt-cert", "", "Path to public key for Key Transparency")
	RootCmd.PersistentFlags().Bool("autoconfig", true, "Fetch config info from the server's /v1/directory/info")
	RootCmd.PersistentFlags().Bool("insecure", false, "Skip TLS checks")

	RootCmd.PersistentFlags().String("vrf", "genfiles/vrf-pubkey.pem", "path to vrf public key")

	RootCmd.PersistentFlags().String("log-key", "genfiles/trillian-log.pem", "Path to public key PEM for Trillian Log server")
	RootCmd.PersistentFlags().String("map-key", "genfiles/trillian-map.pem", "Path to public key PEM for Trillian Map server")

	RootCmd.PersistentFlags().String("client-secret", "", "Path to client_secret.json file for user creds")
	RootCmd.PersistentFlags().String("fake-auth-userid", "", "userid to present to the server as identity for authentication. Only succeeds if fake auth is enabled on the server side.")

	// Global flags for use by subcommands.
	RootCmd.PersistentFlags().DurationP("timeout", "t", 15*time.Second, "Time to wait before operations timeout")
	RootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Print in/out and verification steps")
	if err := viper.BindPFlags(RootCmd.PersistentFlags()); err != nil {
		log.Fatalf("%v", err)
	}
}

// initConfig reads in config file and ENV variables if set.
// initConfig is run during a command's preRun().
func initConfig() {
	viper.AutomaticEnv() // Read in environment variables that match.

	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
		if err := viper.ReadInConfig(); err != nil {
			log.Fatalf("Failed reading config file: %v: %v", viper.ConfigFileUsed(), err)
		}
	} else {
		viper.SetConfigName(".keytransparency")
		viper.AddConfigPath("$HOME")
		if err := viper.ReadInConfig(); err == nil {
			fmt.Println("Using config file:", viper.ConfigFileUsed())
		}
	}
}

// getTokenFromWeb uses config to request a Token.  Returns the retrieved Token.
func getTokenFromWeb(ctx context.Context, config *oauth2.Config) (*oauth2.Token, error) {
	// TODO: replace state token with something random to prevent CSRF.
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}

	tok, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func getCreds(ctx context.Context, clientSecretFile string) (credentials.PerRPCCredentials, error) {
	b, err := ioutil.ReadFile(clientSecretFile)
	if err != nil {
		return nil, err
	}

	config, err := google.ConfigFromJSON(b, authentication.RequiredScopes...)
	if err != nil {
		return nil, err
	}

	tok, err := getTokenFromWeb(ctx, config)
	if err != nil {
		return nil, err
	}
	return oauth.NewOauthAccess(tok), nil
}

func transportCreds() (credentials.TransportCredentials, error) {
	ktCert := viper.GetString("kt-cert")
	insecure := viper.GetBool("insecure")

	switch {
	case insecure: // Impatient insecure.
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // nolint
		}), nil

	case ktCert != "": // Custom CA Cert.
		return credentials.NewClientTLSFromFile(ktCert, "")

	default: // Use the local set of root certs.
		return credentials.NewClientTLSFromCert(nil, ""), nil
	}
}

// userCreds returns PerRPCCredentials. Only one type of credential
// should exist in an RPC call. Fake credentials have the highest priority, followed
// by Client credentials and Service Credentials.
func userCreds(ctx context.Context) (credentials.PerRPCCredentials, error) {
	fakeUserID := viper.GetString("fake-auth-userid")    // Fake user creds.
	clientSecretFile := viper.GetString("client-secret") // Real user creds.

	switch {
	case fakeUserID != "":
		return authentication.GetFakeCredential(fakeUserID), nil
	case clientSecretFile != "":
		return getCreds(ctx, clientSecretFile)
	default:
		return nil, nil
	}
}

func dial(ctx context.Context) (pb.KeyTransparencyClient, error) {
	addr := viper.GetString("kt-url")
	transportCreds, err := transportCreds()
	if err != nil {
		return nil, err
	}

	cc, err := grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(transportCreds))
	if err != nil {
		return nil, fmt.Errorf("grpc.DialContext(%v): %v", addr, err)
	}
	return pb.NewKeyTransparencyClient(cc), nil
}

// GetClient connects to the server and returns a key transparency verification
// client.
func GetClient(ctx context.Context) (*client.Client, error) {
	ktCli, err := dial(ctx)
	if err != nil {
		return nil, err
	}

	config, err := config(ctx, ktCli)
	if err != nil {
		return nil, fmt.Errorf("config: %v", err)
	}

	return client.NewFromConfig(ktCli, config,
		func(lv *tclient.LogVerifier) verifier.LogTracker { return tracker.NewSynchronous(lv) },
	)
}

// config selects a source for and returns the client configuration.
func config(ctx context.Context, client pb.KeyTransparencyClient) (*pb.Directory, error) {
	autoConfig := viper.GetBool("autoconfig")
	directory := viper.GetString("directory")
	switch {
	case autoConfig:
		return client.GetDirectory(ctx, &pb.GetDirectoryRequest{DirectoryId: directory})
	default:
		return readConfigFromDisk()
	}
}

func readConfigFromDisk() (*pb.Directory, error) {
	vrfPubFile := viper.GetString("vrf")
	logPEMFile := viper.GetString("log-key")
	mapPEMFile := viper.GetString("map-key")

	// Log PubKey.
	logPubKey, err := pem.ReadPublicKeyFile(logPEMFile)
	if err != nil {
		return nil, fmt.Errorf("failed to open log public key %v: %v", logPEMFile, err)
	}
	logPubPB, err := der.ToPublicProto(logPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize log public key: %v", err)
	}

	// VRF PubKey
	vrfPubKey, err := pem.ReadPublicKeyFile(vrfPubFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read: %s. %v", vrfPubFile, err)
	}
	vrfPubPB, err := der.ToPublicProto(vrfPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize vrf public key: %v", err)
	}

	// MapPubKey.
	mapPubKey, err := pem.ReadPublicKeyFile(mapPEMFile)
	if err != nil {
		return nil, fmt.Errorf("error reading map public key %v: %v", mapPEMFile, err)
	}
	mapPubPB, err := der.ToPublicProto(mapPubKey)
	if err != nil {
		return nil, fmt.Errorf("error seralizeing map public key: %v", err)
	}

	return &pb.Directory{
		Log: &trillian.Tree{
			HashStrategy: trillian.HashStrategy_OBJECT_RFC6962_SHA256,
			PublicKey:    logPubPB,
		},
		Map: &trillian.Tree{
			HashStrategy: trillian.HashStrategy_CONIKS_SHA256,
			PublicKey:    mapPubPB,
		},
		Vrf: vrfPubPB,
	}, nil
}
