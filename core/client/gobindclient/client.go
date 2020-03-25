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

// Package gobindclient contains a gobind friendly implementation of a KeyTransparency Client able to make
// GetUser requests to a KT server and verify the soundness of the responses.
package gobindclient

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/client/multi"
	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/client/verifier"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	tclient "github.com/google/trillian/client"
)

var (
	clients = make(map[string]*client.Client)

	timeout = 500 * time.Millisecond

	multiLogWriter = multi.NewWriter(os.Stderr)

	// Vlog is the verbose logger. By default it outputs to stderr (logcat on Android), but other destination can be
	// added through the AddVerboseLogsDestination method.
	Vlog = log.New(multiLogWriter, "", log.LstdFlags)
)

func init() {
	client.Vlog = log.New(multiLogWriter, "", log.LstdFlags)
}

// AddVerboseLogsDestination instructs the logger of the gobindclient package to also write all log statements to the provided writer.
func AddVerboseLogsDestination(writer LogWriter) {
	multiLogWriter.AddWriter(writer)
}

// LogWriter is a local copy of the io.Writer interface which can be implemented in Java. Used to redirect logs.
type LogWriter interface {
	Write(p []byte) (n int, err error)
}

// SetTimeout sets the timeout (in milliseconds) used for all rpc network requests.
func SetTimeout(ms int32) {
	timeout = time.Duration(ms) * time.Millisecond
}

// AddKtServer creates a new grpc client to handle connections to the ktURL server and adds it to the global map of clients.
func AddKtServer(ktURL string, insecureTLS bool, ktTLSCertPEM []byte) error {
	if _, exists := clients[ktURL]; exists {
		return fmt.Errorf("the KtServer connection for %v already exists", ktURL)
	}

	// TODO Add URL validation here.

	cc, err := dial(ktURL, insecureTLS, ktTLSCertPEM)
	if err != nil {
		return fmt.Errorf("error dialing %v: %v", ktURL, err)
	}

	ktClient := pb.NewKeyTransparencyClient(cc)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	config, err := ktClient.GetDirectory(ctx, &pb.GetDirectoryRequest{})
	if err != nil {
		return fmt.Errorf("error getting config: %v", err)
	}

	// TODO(gbelvin): Supply the config externally so that it can be built into the client.
	Vlog.Print("Warning: Key material from the server will be trusted.")

	client, err := client.NewFromConfig(ktClient, config,
		func(lv *tclient.LogVerifier) verifier.LogTracker { return tracker.NewSynchronous(lv) },
	)
	if err != nil {
		return fmt.Errorf("error adding the KtServer: %v", err)
	}

	clients[ktURL] = client
	return nil
}

// GetUser retrieves an entry from the ktURL server and verifies the soundness of the corresponding proofs.
func GetUser(ktURL, userID string) ([]byte, error) {
	client, exists := clients[ktURL]
	if !exists {
		return nil, fmt.Errorf("a connection to %v does not exist. Please call AddKtServer first", ktURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, entry, err := client.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("client.GetUser(%v): %v", userID, err)
	}
	// TODO(amarcedone): Consider returning or persisting slr to verify consistency over time.
	return entry, nil
}

func dial(ktURL string, insecureTLS bool, ktTLSCertPEM []byte) (*grpc.ClientConn, error) {
	creds, err := transportCreds(ktURL, insecureTLS, ktTLSCertPEM)
	if err != nil {
		return nil, err
	}

	cc, err := grpc.Dial(ktURL, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, err
	}
	return cc, nil
}

func transportCreds(ktURL string, insecure bool, ktTLSCertPEM []byte) (credentials.TransportCredentials, error) {
	host, _, err := net.SplitHostPort(ktURL)
	if err != nil {
		return nil, err
	}

	switch {
	case insecure: // Impatient insecure.
		Vlog.Printf("Warning: Skipping verification of KT Server's TLS certificate.")
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true, // nolint: gosec
		}), nil

	case len(ktTLSCertPEM) != 0: // Custom CA Cert.
		cp := x509.NewCertPool()
		if !cp.AppendCertsFromPEM(ktTLSCertPEM) {
			return nil, fmt.Errorf("failed to append certificates")
		}
		creds := credentials.NewTLS(&tls.Config{ServerName: host, RootCAs: cp})
		return creds, nil

	default: // Use the local set of root certs.
		return credentials.NewClientTLSFromCert(nil, host), nil
	}
}
