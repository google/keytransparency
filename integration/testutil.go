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
	"io/ioutil"
	"net"
	"net/http/httptest"
	"testing"

	"github.com/gdbelvin/e2e-key-server/appender"
	"github.com/gdbelvin/e2e-key-server/client"
	"github.com/gdbelvin/e2e-key-server/commitments"
	"github.com/gdbelvin/e2e-key-server/integration/ctutil"
	"github.com/gdbelvin/e2e-key-server/keyserver"
	"github.com/gdbelvin/e2e-key-server/mutator/entry"
	"github.com/gdbelvin/e2e-key-server/queue"
	"github.com/gdbelvin/e2e-key-server/signatures"
	"github.com/gdbelvin/e2e-key-server/signer"
	"github.com/gdbelvin/e2e-key-server/tree/sparse/sqlhist"
	"github.com/gdbelvin/e2e-key-server/vrf"
	"github.com/gdbelvin/e2e-key-server/vrf/p256"

	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"

	v2pb "github.com/gdbelvin/e2e-key-server/proto/security_e2ekeys_v2"
)

const (
	clusterSize = 1
	mapID       = "testID"
)

func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("sql.Open(): %v", err)
	}
	return db
}

func Listen(t testing.TB) (string, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		t.Fatal("Failed to parse listener address: %v", err)
	}
	addr := "localhost:" + port
	return addr, lis
}

func openPrivateKey(t testing.TB) *signatures.SignatureSigner {
	file := "../testdata/p256-key.pem"
	pem, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatalf("Failed to read file %v: %v", file, err)
	}
	key, _, err := signatures.PrivateKeyFromPEM(pem)
	sig, err := signatures.NewSignatureSigner(key)
	if err != nil {
		t.Fatal("Failed to create signer: %v", err)
	}
	return sig
}

func openPublicKey(t testing.TB) *signatures.SignatureVerifier {
	file := "../testdata/p256-pubkey.pem"
	pem, err := ioutil.ReadFile(file)
	if err != nil {
		t.Fatalf("Failed to read file %v: %v", file, err)
	}
	key, _, err := signatures.PublicKeyFromPEM(pem)
	verify, err := signatures.NewSignatureVerifier(key)
	if err != nil {
		t.Fatal("Failed to create signer: %v", err)
	}
	return verify
}

type Env struct {
	GRPCServer *grpc.Server
	V2Server   *keyserver.Server
	Conn       *grpc.ClientConn
	Client     *client.Client
	Signer     *signer.Signer
	db         *sql.DB
	clus       *integration.ClusterV3
	VrfPriv    vrf.PrivateKey
	Cli        v2pb.E2EKeyServiceClient
	mapLog     *httptest.Server
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	hs := ctutil.CtServer(t)
	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	sqldb := NewDB(t)

	// Common data structures.
	queue := queue.New(clus.RandClient(), mapID)
	tree := sqlhist.New(sqldb, mapID)
	appender := appender.New(sqldb, mapID, hs.URL)
	vrfPriv, vrfPub := p256.GenerateKey()
	mutator := entry.New()

	commitments := commitments.New(sqldb, mapID)
	server := keyserver.New(commitments, queue, tree, appender, vrfPriv, mutator)
	s := grpc.NewServer()
	v2pb.RegisterE2EKeyServiceServer(s, server)

	signer := signer.New(queue, tree, mutator, appender, openPrivateKey(t))
	signer.CreateEpoch()

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}
	cli := v2pb.NewE2EKeyServiceClient(cc)
	client := client.New(cli, vrfPub, hs.URL, openPublicKey(t))
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
