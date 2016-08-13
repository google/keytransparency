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

// A command line client for Key Transparency.
// Provides authenticated requests for Google accounts.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"time"

	"github.com/google/key-transparency/authentication"
	"github.com/google/key-transparency/client"
	"github.com/google/key-transparency/vrf"
	"github.com/google/key-transparency/vrf/p256"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

var (
	clientSecretFile = flag.String("oauth", "", "path to client secrets")
	vrfPubFile       = flag.String("vrf", "testdata/public_vrf_key.dat", "path to vrf public key")
	ctURL            = flag.String("ct", "", "URL of Certificate Transparency server")
	mapURL           = flag.String("map", "", "URL of Key Transparency server")
	user             = flag.String("user", "", "Email of the user to query")
	get              = flag.Bool("get", true, "Get the current key")
)

const (
	defaultTimeout = 0 * time.Second
)

func readVrfKey() (vrf.PublicKey, error) {
	b, err := ioutil.ReadFile(*vrfPubFile)
	if err != nil {
		return nil, fmt.Errorf("Error reading vrf public key: %v, %v", *vrfPubFile, err)
	}
	v, err := p256.ParsePublicKey(b)
	if err != nil {
		return nil, fmt.Errorf("Error parsing vrf public key: %v", err)
	}
	return v, nil
}

// getTokenFromWeb uses config to request a Token.  Returns the retrieved Token.
func getTokenFromWeb(config *oauth2.Config) *oauth2.Token {
	// TODO: replace state token with something random to prevent CSRF.
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOnline)
	fmt.Printf("Go to the following link in your browser then type the "+
		"authorization code: \n%v\n", authURL)

	var code string
	if _, err := fmt.Scan(&code); err != nil {
		log.Fatalf("Unable to read authorization code %v", err)
	}

	tok, err := config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Fatalf("Unable to retrieve token from web %v", err)
	}
	log.Printf("Got Token: %#v", tok)
	return tok
}

func getCreds() credentials.PerRPCCredentials {
	b, err := ioutil.ReadFile(*clientSecretFile)
	if err != nil {
		log.Fatalf("Unable to read client secret file: %v", err)
	}

	config, err := google.ConfigFromJSON(b, authentication.RequiredScopes...)
	if err != nil {
		log.Fatalf("Unable to parse client secret file to config: %v", err)
	}

	tok := getTokenFromWeb(config)
	return oauth.NewOauthAccess(tok)
}

func main() {
	flag.Parse()
	ctx := context.Background()
	ctx, _ = context.WithTimeout(ctx, DefaultTimeout)
	opts := []grpc.DialOption{grpc.WithInsecure()} // TODO: change
	if *clientSecretFile != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(getCreds()))
	}
	cc, err := grpc.Dial(*mapURL, opts...)
	if err != nil {
		log.Fatalf("Error Dialing %v: %v", *mapURL, err)
	}
	cli := pb.NewKeyTransparencyServiceClient(cc)
	vrfKey, err := readVrfKey()
	if err != nil {
		log.Fatalf("Error reading VRF key: %v", err)
	}
	c := client.New(cli, vrfKey, *ctURL)

	switch {
	case *get:
		profile, err := c.GetEntry(ctx, *user)
		if err != nil {
			log.Fatalf("GetEntry error: %v", err)
		}
		log.Printf("Profile for %v:\n%+v", *user, profile)

	default:
		log.Printf("Nothing to do. Exiting.")
	}
}
