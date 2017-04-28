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
	"crypto"
	"database/sql"
	"log"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/keytransparency/cmd/keytransparency-client/grpcc"
	"github.com/google/keytransparency/core/admin"
	"github.com/google/keytransparency/core/appender"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mapserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/signer"
	"github.com/google/keytransparency/core/testutil/ctutil"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/sql/sequenced"
	"github.com/google/keytransparency/impl/sql/sqlhist"
	"github.com/google/keytransparency/impl/transaction"
	"github.com/google/keytransparency/integration/fake"

	"github.com/google/trillian/crypto/keys"
	"github.com/google/trillian/util"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/google/keytransparency/impl/proto/keytransparency_v1_service"
	"github.com/google/trillian"
)

const (
	mapID = 0
	logID = 0
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
	Signer     *signer.Signer
	db         *sql.DB
	Factory    *transaction.Factory
	VrfPriv    vrf.PrivateKey
	Cli        pb.KeyTransparencyServiceClient
	mapLog     *httptest.Server
}

func staticKeyPair() (crypto.Signer, crypto.PublicKey, error) {
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
	sig, err := keys.NewFromPrivatePEM(sigPriv, "")
	if err != nil {
		return nil, nil, err
	}

	ver, err := keys.NewFromPublicPEM(sigPub)
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
	sqldb := NewDB(t)

	sig, verifier, err := staticKeyPair()
	if err != nil {
		t.Fatalf("Failed to load signing keypair: %v", err)
	}

	// Common data structures.
	mutations, err := mutations.New(sqldb, mapID)
	if err != nil {
		log.Fatalf("Failed to create mutations object: %v", err)
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

	// Map server
	factory := transaction.NewFactory(sqldb)
	tree, err := sqlhist.New(context.Background(), mapID, factory)
	if err != nil {
		t.Fatalf("Failed to create SQL history: %v", err)
	}
	sths, err := sequenced.New(sqldb, mapID)
	if err != nil {
		t.Fatalf("sequenced.New(): %v", err)
	}
	clock := util.NewFakeTimeSource(time.Now())
	mapsvr := mapserver.New(mapID, tree, factory, sths, sig, clock)
	// Configure map. TODO: setup map through admin interface.
	if _, err := mapsvr.SetLeaves(context.Background(), &trillian.SetMapLeavesRequest{
		MapId: mapID,
		MapperData: &trillian.MapperMetadata{
			HighestFullyCompletedSeq: int64(0),
		},
	}); err != nil {
		t.Fatalf("SetLeaves(): %v", err)
	}

	server := keyserver.New(logID, mapID, mapsvr, commitments, vrfPriv, mutator,
		auth, factory, mutations)
	s := grpc.NewServer()
	pb.RegisterKeyTransparencyServiceServer(s, server)

	// Signer
	admin := admin.NewStatic()
	if err := admin.AddLog(logID, fake.NewFakeTrillianClient()); err != nil {
		t.Fatalf("failed to add log to admin: %v", err)
	}
	sthsLog := appender.NewTrillian(admin)
	signer := signer.New("", mapID, mapsvr, logID, sthsLog, mutator, mutations, factory)

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%v) = %v", addr, err)
	}
	cli := pb.NewKeyTransparencyServiceClient(cc)
	client := grpcc.New(mapID, cli, vrfPub, verifier, fake.NewFakeTrillianLogVerifier())
	client.RetryCount = 0

	return &Env{s, server, cc, client, signer, sqldb, factory, vrfPriv, cli, hs}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close(t *testing.T) {
	env.Conn.Close()
	env.GRPCServer.Stop()
	env.db.Close()
	env.mapLog.Close()
}
