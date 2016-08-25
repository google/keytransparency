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
	"time"

	"github.com/google/key-transparency/cmd/client/grpcc"
	"github.com/google/key-transparency/core/client/ctlog"
	"github.com/google/key-transparency/core/signatures"
	"github.com/google/key-transparency/core/vrf"
	"github.com/google/key-transparency/core/vrf/p256"
	"github.com/google/key-transparency/impl/google/authentication"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	pb "github.com/google/key-transparency/impl/proto/kt_service_v1"
)

var cfgFile string

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "key-transparency-client",
	Short: "A client for interacting with the key transparency server",
	Long: `The key transparency client retrieves and sets keys in the 
key transparency server.  The client verifies all cryptographic proofs the
server provides to ensure that account data is accurate.`,
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatalf("%v", err)
	}
}

// Global flags for use by subcommands.
var (
	verbose bool
)

func init() {
	cobra.OnInitialize(initConfig)
	RootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.key-transparency.yaml)")
	RootCmd.PersistentFlags().String("vrf", "testdata/vrf-pubkey.pem", "path to vrf public key")
	RootCmd.PersistentFlags().String("ct-url", "", "URL of Certificate Transparency server")
	RootCmd.PersistentFlags().String("ct-key", "testdata/ct-server-key-public.pem", "Path to public key PEM for Certificate Transparency server")
	RootCmd.PersistentFlags().String("kt-url", "", "URL of Key Transparency server")
	RootCmd.PersistentFlags().String("kt-key", "testdata/server.crt", "Path to public key for Key Transparency")

	RootCmd.PersistentFlags().String("kt-sig", "testdata/p256-pubkey.pem", "Path to public key for signed map heads")

	// Global flags for use by subcommands.
	RootCmd.PersistentFlags().DurationP("timeout", "t", 3*time.Second, "Time to wait before operations timeout")
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
		viper.SetConfigName(".key-transparency")
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
func getTokenFromWeb(config *oauth2.Config) (*oauth2.Token, error) {
	// TODO: replace state token with something random to prevent CSRF.
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		return nil, err
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		return nil, err
	}
	return tok, nil
}

func getCreds(clientSecretFile string) (credentials.PerRPCCredentials, error) {
	b, err := ioutil.ReadFile(clientSecretFile)
	if err != nil {
		return nil, err
	}

	config, err := google.ConfigFromJSON(b, authentication.RequiredScopes...)
	if err != nil {
		return nil, err
	}

	tok, err := getTokenFromWeb(config)
	if err != nil {
		return nil, err
	}
	return oauth.NewOauthAccess(tok), nil
}

func readSignatureVerifier(ktPEM string) (*signatures.Verifier, error) {
	pem, err := ioutil.ReadFile(ktPEM)
	if err != nil {
		return nil, err
	}
	pk, _, err := signatures.PublicKeyFromPEM(pem)
	if err != nil {
		return nil, err
	}
	ver, err := signatures.NewVerifier(pk)
	if err != nil {
		return nil, err
	}
	return ver, nil
}

func getClient(cc *grpc.ClientConn, vrfPubFile, ktSig, ctURL, ctPEM string) (*grpcc.Client, error) {
	// Create CT client.
	pem, err := ioutil.ReadFile(ctPEM)
	if err != nil {
		return nil, fmt.Errorf("error reading ctPEM: %v", err)
	}
	ctClient, err := ctlog.New(pem, ctURL)
	if err != nil {
		return nil, fmt.Errorf("error creating CT client: %v", err)
	}

	// Create Key Transparency client.
	vrfKey, err := readVrfKey(vrfPubFile)
	if err != nil {
		return nil, err
	}
	verifier, err := readSignatureVerifier(ktSig)
	if err != nil {
		return nil, fmt.Errorf("error reading key transparency PEM: %v", err)
	}
	cli := pb.NewKeyTransparencyServiceClient(cc)
	return grpcc.New(cli, vrfKey, verifier, ctClient), nil
}

func dial(ktURL, caFile, clientSecretFile string) (*grpc.ClientConn, error) {
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

	if clientSecretFile != "" {
		creds, err := getCreds(clientSecretFile)
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

// GetClient connects to the server and returns a key transpency verification
// client.
func GetClient(clientSecretFile string) (*grpcc.Client, error) {
	ktURL := viper.GetString("kt-url")
	ktPEM := viper.GetString("kt-key")
	ktSig := viper.GetString("kt-sig")
	ctURL := viper.GetString("ct-url")
	ctPEM := viper.GetString("ct-key")
	vrfFile := viper.GetString("vrf")
	cc, err := dial(ktURL, ktPEM, clientSecretFile)
	if err != nil {
		return nil, fmt.Errorf("Error Dialing %v: %v", ktURL, err)
	}
	c, err := getClient(cc, vrfFile, ktSig, ctURL, ctPEM)
	if err != nil {
		return nil, fmt.Errorf("Error creating client: %v", err)
	}
	return c, nil
}
