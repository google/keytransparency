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
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/client/kt"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	gauth "github.com/google/keytransparency/impl/google/authentication"
	pb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"

	"github.com/google/trillian"
	"github.com/google/trillian/client"
	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/merkle/hashers"
	_ "github.com/google/trillian/merkle/objhasher" // Register objhasher
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"
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
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		if verbose {
			grpcc.Vlog = log.New(os.Stdout, "", log.LstdFlags)
			kt.Vlog = log.New(os.Stdout, "", log.LstdFlags)
		}
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatalf("%v", err)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.keytransparency.yaml)")

	RootCmd.PersistentFlags().String("kt-url", "", "URL of Key Transparency server")
	RootCmd.PersistentFlags().String("kt-cert", "genfiles/server.crt", "Path to public key for Key Transparency")
	RootCmd.PersistentFlags().String("vrf", "genfiles/vrf-pubkey.pem", "path to vrf public key")

	RootCmd.PersistentFlags().String("log-key", "genfiles/trillian-log.pem", "Path to public key PEM for Trillian Log server")
	RootCmd.PersistentFlags().String("map-key", "genfiles/trillian-map.pem", "Path to public key PEM for Trillian Map server")

	RootCmd.PersistentFlags().String("fake-auth-userid", "", "userid to present to the server as identity for authentication. Only succeeds if fake auth is enabled on the server side.")

	// Global flags for use by subcommands.
	RootCmd.PersistentFlags().DurationP("timeout", "t", 3*time.Minute, "Time to wait before operations timeout")
	RootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Print in/out and verification steps")
	if err := viper.BindPFlags(RootCmd.PersistentFlags()); err != nil {
		log.Fatalf("%v", err)
	}
}

// initConfig reads in config file and ENV variables if set.
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

func readVrfKey(vrfPubFile string) (vrf.PublicKey, error) {
	b, err := ioutil.ReadFile(vrfPubFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading vrf public key: %v, %v", vrfPubFile, err)
	}
	v, err := p256.NewVRFVerifierFromPEM(b)
	if err != nil {
		return nil, fmt.Errorf("Error parsing vrf public key: %v", err)
	}
	return v, nil
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

	config, err := google.ConfigFromJSON(b, gauth.RequiredScopes...)
	if err != nil {
		return nil, err
	}

	tok, err := getTokenFromWeb(ctx, config)
	if err != nil {
		return nil, err
	}
	return oauth.NewOauthAccess(tok), nil
}

func getServiceCreds(serviceKeyFile string) (credentials.PerRPCCredentials, error) {
	b, err := ioutil.ReadFile(serviceKeyFile)
	if err != nil {
		return nil, err
	}
	return oauth.NewServiceAccountFromKey(b, gauth.RequiredScopes...)
}

func dial(ktURL, caFile, clientSecretFile string, serviceKeyFile string) (*grpc.ClientConn, error) {
	ctx := context.Background()
	var opts []grpc.DialOption
	if true {
		host, _, err := net.SplitHostPort(ktURL)
		if err != nil {
			return nil, err
		}
		var creds credentials.TransportCredentials
		if caFile != "" {
			var err error
			creds, err = credentials.NewClientTLSFromFile(caFile, host)
			if err != nil {
				return nil, err
			}
		} else {
			// Use the local set of root certs.
			creds = credentials.NewClientTLSFromCert(nil, host)
		}
		opts = append(opts, grpc.WithTransportCredentials(creds))
	}

	// Add authentication information for the grpc. Only one type of credential
	// should exist in an RPC call. Fake credentials have the highest priority, followed
	// by Client credentials and Service Credentials.
	fakeUserID := viper.GetString("fake-auth-userid")
	switch {
	case fakeUserID != "":
		opts = append(opts, grpc.WithPerRPCCredentials(
			authentication.GetFakeCredential(fakeUserID)))
	case clientSecretFile != "":
		creds, err := getCreds(ctx, clientSecretFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	case serviceKeyFile != "":
		creds, err := getServiceCreds(serviceKeyFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.WithPerRPCCredentials(creds))
	}

	cc, err := grpc.Dial(ktURL, opts...)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

// GetClient connects to the server and returns a key transparency verification
// client.
func GetClient(clientSecretFile string) (*grpcc.Client, error) {
	ktURL := viper.GetString("kt-url")
	ktCert := viper.GetString("kt-cert")
	vrfPubFile := viper.GetString("vrf")
	logPEMFile := viper.GetString("log-key")
	mapPEMFile := viper.GetString("map-key")
	serviceKeyFile := viper.GetString("service-key") // Anonymous user creds.

	// Client Connection.
	cc, err := dial(ktURL, ktCert, clientSecretFile, serviceKeyFile)
	if err != nil {
		return nil, fmt.Errorf("Error Dialing %v: %v", ktURL, err)
	}

	// Log PubKey.
	logPubKey, err := keys.NewFromPublicPEMFile(logPEMFile)
	if err != nil {
		return nil, fmt.Errorf("Failed to open public key %v: %v", logPubKey, err)
	}

	// Hasher.
	hasher, err := hashers.NewLogHasher(trillian.HashStrategy_OBJECT_RFC6962_SHA256)
	if err != nil {
		return nil, fmt.Errorf("Failed retrieving LogHasher from registry: %v", err)
	}

	// VRF PubKey.
	vrfPubKey, err := readVrfKey(vrfPubFile)
	if err != nil {
		return nil, err
	}

	// MapPubKey.
	mapPubKey, err := keys.NewFromPublicPEMFile(mapPEMFile)
	if err != nil {
		return nil, fmt.Errorf("error reading key transparency PEM: %v", err)
	}

	logVerifier := client.NewLogVerifier(hasher, logPubKey)
	KTClientConn := pb.NewKeyTransparencyServiceClient(cc)
	return grpcc.New(KTClientConn, vrfPubKey, mapPubKey, logVerifier), nil
}
