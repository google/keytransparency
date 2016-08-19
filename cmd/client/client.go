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
	"net"
	"time"

	"github.com/google/key-transparency/core/client"
	"github.com/google/key-transparency/core/signatures"
	"github.com/google/key-transparency/core/vrf"
	"github.com/google/key-transparency/core/vrf/p256"
	"github.com/google/key-transparency/impl/google/authentication"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/oauth"

	pb "github.com/google/key-transparency/impl/proto/kt_service_v1"
)

var (
	// Required parameters.
	vrfPubFile = flag.String("vrf", "testdata/vrf-pubkey.pem", "path to vrf public key")
	ctURL      = flag.String("ct-url", "", "URL of Certificate Transparency server")
	ctPEM      = flag.String("ct-key", "testdata/ct-server-key-public.pem", "Path to public key PEM for Certificate Transparency server")
	ktURL      = flag.String("kt-url", "", "URL of Key Transparency server")
	ktPEM      = flag.String("kt-key", "testdata/server.crt", "Path to public key for Key Transparency")
	ktSig      = flag.String("kt-sig", "testdata/p256-pubkey.pem", "Path to public key for signed map heads")
	user       = flag.String("user", "", "Email of the user to query")

	// Optional parameters with sane defaults.
	timeout = flag.Duration("timeout", 500, "Milliseconds to wait before operations timeout")

	// Get parameters.
	get = flag.Bool("get", true, "Get the current key")

	// Update parameters.
	clientSecretFile = flag.String("secret", "", "path to client secrets")
)

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

func getClient(cc *grpc.ClientConn, vrfPubFile, ktSig, ctURL, ctPEM string) (*client.Client, error) {
	// Create CT client.
	pem, err := ioutil.ReadFile(ctPEM)
	if err != nil {
		return nil, fmt.Errorf("error reading ctPEM: %v", err)
	}
	ctClient, err := client.NewLogVerifier(pem, ctURL)
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
	return client.New(cli, vrfKey, verifier, ctClient), nil
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

func main() {
	flag.Parse()

	cc, err := dial(*ktURL, *ktPEM, *clientSecretFile)
	if err != nil {
		log.Fatalf("Error Dialing %v: %v", *ktURL, err)
	}
	c, err := getClient(cc, *vrfPubFile, *ktSig, *ctURL, *ctPEM)
	if err != nil {
		log.Fatalf("Error creating client: %v", err)
	}

	ctx, _ := context.WithTimeout(context.Background(), *timeout*time.Millisecond)
	switch {
	case *get:
		profile, err := c.GetEntry(ctx, *user)
		if err != nil {
			log.Fatalf("GetEntry failed: %v", err)
		}
		log.Printf("Profile for %v:\n%+v", *user, profile)
		// TODO: Print verification
	default:
		log.Printf("Nothing to do. Exiting.")
	}
}
