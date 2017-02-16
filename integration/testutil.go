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

	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/signatures/factory"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/signer"
	"github.com/google/keytransparency/core/testutil/ctutil"
	"github.com/google/keytransparency/core/vrf"
	"github.com/google/keytransparency/core/vrf/p256"
	"github.com/google/keytransparency/impl/etcd/queue"
	"github.com/google/keytransparency/impl/sql/appender"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
)

const (
	clusterSize = 1
	mapID       = "testID"
)

// NewDB creates a new in-memory database for testing.
func NewDB(t testing.TB) *sql.DB {
	db, err := sql.Open("sqlite3", "file:dummy.db?mode=memory&cache=shared")
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
	Client     *grpcc.Client
	Queue      *queue.Queue
	Signer     *signer.Signer
	db         *sql.DB
	Factory    *transaction.Factory
	clus       *integration.ClusterV3
	VrfPriv    vrf.PrivateKey
	Cli        pb.KeyTransparencyServiceClient
	mapLog     *httptest.Server
}

func staticKeyPair() (signatures.Signer, signatures.Verifier, error) {
	sigPriv := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHgSC8WzQK0bxSmfJWUeMP5GdndqUw8zS1dCHQ+3otj/oAoGCCqGSM49
AwEHoUQDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhWf5JqSoyp0uiL8LeNYyj5vgkl
K8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END EC PRIVATE KEY-----`
	sigPub := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhW
f5JqSoyp0uiL8LeNYyj5vgklK8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END PUBLIC KEY-----`
	signatures.Rand = DevZero{}
	sig, err := factory.NewSignerFromPEM([]byte(sigPriv))
	if err != nil {
		return nil, nil, err
	}

	ver, err := factory.NewVerifierFromPEM([]byte(sigPub))
	if err != nil {
		return nil, nil, err
	}
	return sig, ver, nil
}

func staticVRF() (vrf.PrivateKey, vrf.PublicKey, error) {
	priv := `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIHgSC8WzQK0bxSmfJWUeMP5GdndqUw8zS1dCHQ+3otj/oAoGCCqGSM49
AwEHoUQDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhWf5JqSoyp0uiL8LeNYyj5vgkl
K8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END EC PRIVATE KEY-----`
	pub := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE5AV2WCmStBt4N2Dx+7BrycJFbxhW
f5JqSoyp0uiL8LeNYyj5vgklK8pLcyDbRqch9Az8jXVAmcBAkvaSrLW8wQ==
-----END PUBLIC KEY-----`
	vrf, err := p256.NewVRFSignerFromPEM([]byte(priv))
	if err != nil {
		return nil, nil, err
	}
	verfier, err := p256.NewVRFVerifierFromPEM([]byte(pub))
	if err != nil {
		return nil, nil, err
	}
	return vrf, verfier, nil
}

// DevZero is an io.Reader that returns 0's
type DevZero struct{}

// Read returns 0's
func (DevZero) Read(b []byte) (n int, err error) {
	for i := range b {
		b[i] = 0
	}

	return len(b), nil
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	hs := ctutil.NewCTServer(t)
	clus := integration.NewClusterV3(t, &integration.ClusterConfig{Size: clusterSize})
	etcdCli := clus.RandClient()
	sqldb := NewDB(t)

	sig, verifier, err := staticKeyPair()
	if err != nil {
		t.Fatalf("Failed to load signing keypair: %v", err)
	}

	// Common data structures.
	factory := transaction.NewFactory(sqldb, etcdCli)
	queue := queue.New(context.Background(), etcdCli, mapID, factory)
	tree, err := sqlhist.New(context.Background(), sqldb, mapID, factory)
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	sths, err := appender.New(context.Background(), sqldb, mapID, hs.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create STH appender: %v", err)
	}
	mutations, err := appender.New(context.Background(), nil, mapID, "", nil)
	if err != nil {
		t.Fatalf("Failed to create mutation appender: %v", err)
	}
	vrfPriv, vrfPub, err := staticVRF()
	if err != nil {
		t.Fatalf("Failed to load vrf keypair: %v", err)
	}
	mutator := entry.New()
	auth := authentication.NewFake()

	commitments, err := commitments.New(sqldb, mapID)
	if err != nil {
		t.Fatalf("Failed to create committer: %v", err)
	}
	server := keyserver.New(commitments, queue, tree, sths, vrfPriv, mutator, auth, factory)
	s := grpc.NewServer()
	pb.RegisterKeyTransparencyServiceServer(s, server)

	signer := signer.New("", queue, tree, mutator, sths, mutations, sig)
	signer.FakeTime()
	txn, err := factory.NewDBTxn(context.Background())
	if err != nil {
		t.Fatalf("Failed to create transaction: %v", err)
	}
	if err := signer.CreateEpoch(context.Background(), txn); err != nil {
		t.Fatalf("Failed to create epoch: %v", err)
	}
	if err := txn.Commit(); err != nil {
		t.Fatalf("Failed to commit transaction: %v", err)
	}

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%v) = %v", addr, err)
	}
	cli := pb.NewKeyTransparencyServiceClient(cc)
	client := grpcc.New(mapID, cli, vrfPub, verifier, fakeLog{})
	client.RetryCount = 0

	return &Env{s, server, cc, client, queue, signer, sqldb, factory, clus, vrfPriv, cli, hs}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close(t *testing.T) {
	env.Conn.Close()
	env.GRPCServer.Stop()
	env.db.Close()
	env.clus.Terminate(t)
	env.mapLog.Close()
}
