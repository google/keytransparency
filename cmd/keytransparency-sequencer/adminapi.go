// Copyright 2017 Google Inc. All Rights Reserved.
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
	"database/sql"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/google/keytransparency/core/adminservice"
	"github.com/google/keytransparency/core/crypto/keymaster"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	ktpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"
)

var (
	keyStoreFile = flag.String("keystore", "genfiles/.keystore", "Path to keystore file")
	vrfPath      = flag.String("vrf", "genfiles/vrf-key.pem", "Path to VRF private key")
)

func openVRFKey() vrf.PrivateKey {
	vrfBytes, err := ioutil.ReadFile(*vrfPath)
	if err != nil {
		glog.Exitf("Failed opening VRF private key: %v", err)
	}
	vrfPriv, err := p256.NewVRFSignerFromPEM(vrfBytes)
	if err != nil {
		glog.Exitf("Failed parsing VRF private key: %v", err)
	}
	return vrfPriv
}

func readKeyStoreFile() (*keymaster.KeyMaster, error) {
	store := keymaster.New()
	// Authorized keys file might not exist.
	data, err := ioutil.ReadFile(*keyStoreFile)
	if err != nil {
		return nil, fmt.Errorf("reading keystore file %v failed: %v", *keyStoreFile, err)
	}
	if err = keymaster.Unmarshal(data, store); err != nil {
		return nil, fmt.Errorf("keystore.Unmarshak() failed: %v", err)
	}
	return store, nil
}

func grpcGatewayMux(addr string) (*runtime.ServeMux, error) {
	ctx := context.Background()

	creds, err := credentials.NewClientTLSFromFile(*certFile, "")
	if err != nil {
		return nil, err
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(creds)}

	gwmux := runtime.NewServeMux()
	if err := ktpb.RegisterKeyTransparencyAdminServiceHandlerFromEndpoint(ctx, gwmux, addr, dopts); err != nil {
		return nil, err
	}

	return gwmux, nil
}

func adminAPI(sqldb *sql.DB,
	tmap trillian.TrillianMapClient,
	tlog trillian.TrillianLogClient) (*grpc.Server, *runtime.ServeMux) {

	creds, err := credentials.NewServerTLSFromFile(*certFile, *keyFile)
	if err != nil {
		glog.Exitf("Failed to load server credentials %v", err)
	}

	commitments, err := commitments.New(sqldb, *mapID)
	if err != nil {
		glog.Exitf("Failed to create committer: %v", err)
	}
	mutations, err := mutations.New(sqldb, *mapID)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}
	vrfPriv := openVRFKey()
	mutator := entry.New()
	factory := transaction.NewFactory(sqldb)

	store, err := readKeyStoreFile()
	if err != nil {
		glog.Exitf("Failed to read keystore file: %v", err)
	}

	svr := adminservice.New(
		*mapID, tmap,
		*logID, tlog,
		vrfPriv,
		mutator, mutations,
		factory, commitments,
		store.Signers())

	grpcServer := grpc.NewServer(
		grpc.Creds(creds),
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)
	ktpb.RegisterKeyTransparencyAdminServiceServer(grpcServer, svr)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	gwmux, err := grpcGatewayMux(*addr)
	if err != nil {
		glog.Exitf("Failed setting up REST proxy: %v", err)
	}

	return grpcServer, gwmux
}
