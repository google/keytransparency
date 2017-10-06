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

package main

import (
	"crypto/tls"
	"flag"
	"net"
	"net/http"
	"time"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/monitor/storage"
	"github.com/google/keytransparency/impl/monitor"
	"github.com/google/keytransparency/impl/monitor/client"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keys/pem"
	"github.com/google/trillian/merkle/hashers"

	"github.com/golang/glog"
	"github.com/grpc-ecosystem/go-grpc-prometheus"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	cmon "github.com/google/keytransparency/core/monitor"
	spb "github.com/google/keytransparency/core/proto/keytransparency_v1_service"
	kpb "github.com/google/keytransparency/core/proto/keytransparency_v1_types"
	mopb "github.com/google/keytransparency/core/proto/monitor_v1_service"
	mupb "github.com/google/keytransparency/core/proto/mutation_v1_service"
	tlogcli "github.com/google/trillian/client"
	_ "github.com/google/trillian/merkle/coniks"    // Register coniks
	_ "github.com/google/trillian/merkle/objhasher" // Register objhasher
)

var (
	addr     = flag.String("addr", ":8099", "The ip:port combination to listen on")
	keyFile  = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile = flag.String("tls-cert", "genfiles/server.pem", "TLS cert file")

	signingKey         = flag.String("sign-key", "genfiles/monitor_sign-key.pem", "Path to private key PEM for SMH signing")
	signingKeyPassword = flag.String("password", "towel", "Password of the private key PEM file for SMH signing")
	ktURL              = flag.String("kt-url", "localhost:8080", "URL of key-server.")
	insecure           = flag.Bool("insecure", false, "Skip TLS checks")
	ktCert             = flag.String("kt-cert", "genfiles/server.crt", "Path to kt-server's public key")

	pollPeriod = flag.Duration("poll-period", time.Second*5, "Maximum time between polling the key-server. Ideally, this is equal to the min-period of paramerter of the keyserver.")

	// TODO(ismail): expose prometheus metrics: a variable that tracks valid/invalid MHs
	// metricsAddr = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
)

func grpcGatewayMux(addr string) (*runtime.ServeMux, error) {
	ctx := context.Background()
	creds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		return nil, err
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	gwmux := runtime.NewServeMux()
	if err := mopb.RegisterMonitorServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
		return nil, err
	}

	return gwmux, nil
}

func main() {
	flag.Parse()

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	// Create gRPC server.
	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)

	// Connect to the kt-server's mutation API:
	grpcc, err := dial()
	if err != nil {
		glog.Fatalf("Error Dialing %v: %v", ktURL, err)
	}
	mcc := mupb.NewMutationServiceClient(grpcc)

	// Read signing key:
	key, err := pem.ReadPrivateKeyFile(*signingKey, *signingKeyPassword)
	if err != nil {
		glog.Fatalf("Could not create signer from %v: %v", *signingKey, err)
	}
	ctx := context.Background()
	logTree, mapTree, err := getTrees(ctx, grpcc)
	if err != nil {
		glog.Fatalf("Could not read domain info %v:", err)
	}

	store := storage.New()
	srv := monitor.New(store)
	mopb.RegisterMonitorServiceServer(grpcServer, srv)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	// Create HTTP handlers and gRPC gateway.
	gwmux, err := grpcGatewayMux(*addr)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	// Insert handlers for other http paths here.
	mux := http.NewServeMux()
	mux.Handle("/", gwmux)
	logHasher, err := hashers.NewLogHasher(logTree.GetHashStrategy())
	if err != nil {
		glog.Fatalf("Could not initialize log hasher: %v", err)
	}
	logPubKey, err := der.UnmarshalPublicKey(logTree.GetPublicKey().GetDer())
	if err != nil {
		glog.Fatalf("Failed parsing Log public key: %v", err)
	}
	logVerifier := tlogcli.NewLogVerifier(logHasher, logPubKey)

	mon, err := cmon.New(logVerifier, mapTree, crypto.NewSHA256Signer(key), store)
	if err != nil {
		glog.Exitf("Failed to initialize monitor: %v", err)
	}
	// initialize the mutations API client and feed the responses it got
	// into the monitor:
	mutCli := client.New(mcc, *pollPeriod)
	responses, errs := mutCli.StartPolling(1)
	go func() {
		for {
			select {
			case mutResp := <-responses:
				glog.Infof("Received mutations response: %v", mutResp.Epoch)
				if err := mon.Process(mutResp); err != nil {
					glog.Infof("Error processing mutations response: %v", err)
				}
			case err := <-errs:
				// this is OK if there were no mutations in  between:
				// TODO(ismail): handle the case when the known maxDuration has
				// passed and no epoch was issued?
				glog.Infof("Could not retrieve mutations API response %v", err)
			}
		}
	}()

	// Serve HTTP2 server over TLS.
	glog.Infof("Listening on %v", *addr)
	if err := http.ListenAndServeTLS(*addr, *certFile, *keyFile,
		serverutil.GrpcHandlerFunc(grpcServer, mux)); err != nil {
		glog.Errorf("ListenAndServeTLS: %v", err)
	}
}

func dial() (*grpc.ClientConn, error) {
	var opts []grpc.DialOption

	transportCreds, err := transportCreds(*ktURL, *ktCert, *insecure)
	if err != nil {
		return nil, err
	}
	opts = append(opts, grpc.WithTransportCredentials(transportCreds))

	// TODO(ismail): authenticate the monitor to the kt-server:
	cc, err := grpc.Dial(*ktURL, opts...)
	if err != nil {
		return nil, err
	}
	return cc, nil
}

// TODO(ismail): refactor client and monitor to use the same methods
func transportCreds(ktURL string, ktCert string, insecure bool) (credentials.TransportCredentials, error) {
	// copied from keytransparency-client/cmd/root.go: transportCreds
	host, _, err := net.SplitHostPort(ktURL)
	if err != nil {
		return nil, err
	}

	switch {
	case insecure: // Impatient insecure.
		return credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
		}), nil

	case ktCert != "": // Custom CA Cert.
		return credentials.NewClientTLSFromFile(ktCert, host)

	default: // Use the local set of root certs.
		return credentials.NewClientTLSFromCert(nil, host), nil
	}
}

// config selects a source for and returns the client configuration.
func getTrees(ctx context.Context, cc *grpc.ClientConn) (logTree *trillian.Tree, mapTree *trillian.Tree, err error) {
	ktClient := spb.NewKeyTransparencyServiceClient(cc)
	resp, err2 := ktClient.GetDomainInfo(ctx, &kpb.GetDomainInfoRequest{})
	if err2 != nil {
		err = err2
		return
	}
	logTree = resp.GetLog()
	mapTree = resp.GetMap()
	return
}
