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

package integration

import (
	"database/sql"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/authentication"
	"github.com/google/e2e-key-server/client"
	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/mutator/entry"
	"github.com/google/e2e-key-server/queue"
	"github.com/google/e2e-key-server/signatures"
	"github.com/google/e2e-key-server/signer"
	"github.com/google/e2e-key-server/tree/sparse/sqlhist"
	"github.com/google/e2e-key-server/vrf"
	"github.com/google/e2e-key-server/vrf/p256"
	"github.com/google/e2e-key-server/integration/ctutil"

	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
	"google.golang.org/grpc"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
)

const (
	clusterSize = 1
	mapID       = "testID"
)

// NewDB creates a new in-memory database for testing.
func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

// Listen opens a random local port and listens on it.
func Listen(t testing.TB) (string, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatalf("Failed to parse listener address: %v", err)
	}
	addr := "localhost:" + port
	return addr, lis
}

// Env holds a complete testing environment for end-to-end tests.
type Env struct {
	GRPCServer *grpc.Server
	V2Server   *keyserver.Server
	Conn       *grpc.ClientConn
	Client     *client.Client
	Signer     *signer.Signer
	db         *sql.DB
	clus       *integration.ClusterV3
	VrfPriv    vrf.PrivateKey
	Cli        pb.E2EKeyServiceClient
	mapLog     *httptest.Server
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	hs := ctutil.NewCTServer(t)
	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	sqldb := NewDB(t)
	sig, verifier, err := signatures.GenerateKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate signing keypair: %v", err)
	}

	// Common data structures.
	queue := queue.New(clus.RandClient(), mapID)
	tree := sqlhist.New(sqldb, mapID)
	sths := appender.New(sqldb, mapID, hs.URL)
	mutations := appender.New(nil, mapID, "")
	vrfPriv, vrfPub := p256.GenerateKey()
	mutator := entry.New()
	auth := authentication.NewFake()

	commitments := commitments.New(sqldb, mapID)
	server := keyserver.New(commitments, queue, tree, sths, vrfPriv, mutator, auth)
	s := grpc.NewServer()
	pb.RegisterE2EKeyServiceServer(s, server)

	signer := signer.New("", queue, tree, mutator, sths, mutations, sig)
	signer.CreateEpoch()

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%v) = %v", addr, err)
	}
	cli := pb.NewE2EKeyServiceClient(cc)
	client := client.New(cli, vrfPub, hs.URL, verifier)
	client.RetryCount = 0

	return &Env{s, server, cc, client, signer, sqldb, clus, vrfPriv, cli, hs}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close(t *testing.T) {
	env.Conn.Close()
	env.GRPCServer.Stop()
	env.db.Close()
	env.clus.Terminate(t)
	env.mapLog.Close()
}
