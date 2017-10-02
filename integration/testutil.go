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
	"log"
	"net"
	"testing"

	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/client/grpcc"
	"github.com/google/keytransparency/core/crypto/vrf"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/mutation"
	"github.com/google/keytransparency/impl/sql/commitments"
	"github.com/google/keytransparency/impl/sql/mutations"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/testonly/integration"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	cmutation "github.com/google/keytransparency/core/mutation"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1"
	mpb "github.com/google/keytransparency/core/proto/mutation_v1_service"
	stestonly "github.com/google/trillian/storage/testonly"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
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
	mapEnv     *integration.MapEnv
	GRPCServer *grpc.Server
	V2Server   *keyserver.Server
	Conn       *grpc.ClientConn
	Client     *grpcc.Client
	Signer     *sequencer.Sequencer
	db         *sql.DB
	Factory    *transaction.Factory
	VrfPriv    vrf.PrivateKey
	Cli        pb.KeyTransparencyServiceClient
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

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	ctx := context.Background()
	sqldb := NewDB(t)

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx, "keytransparency")
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Configure map.
	treeParams := stestonly.MapTree
	treeParams.HashStrategy = trillian.HashStrategy_CONIKS_SHA512_256
	tree, err := mapEnv.AdminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: treeParams,
	})
	if err != nil {
		t.Fatalf("CreateTree(): %v", err)
	}
	mapID := tree.TreeId
	mapPubKey, err := der.UnmarshalPublicKey(tree.GetPublicKey().GetDer())
	if err != nil {
		t.Fatalf("Failed to load signing keypair: %v", err)
	}

	// Configure log.
	logTree, err := mapEnv.AdminClient.CreateTree(ctx, &trillian.CreateTreeRequest{
		Tree: stestonly.LogTree,
	})
	if err != nil {
		t.Fatalf("CreateTree(): %v", err)
	}
	logID := logTree.GetTreeId()

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
	authz := authorization.New()
	tlog := fake.NewFakeTrillianLogClient()

	factory := transaction.NewFactory(sqldb)
	server := keyserver.New(logID, tlog, mapID, mapEnv.MapClient, mapEnv.AdminClient, commitments,
		vrfPriv, mutator, auth, authz, factory, mutations)
	s := grpc.NewServer()
	msrv := mutation.New(cmutation.New(logID, mapID, tlog, mapEnv.MapClient, mutations, factory))
	pb.RegisterKeyTransparencyServiceServer(s, server)
	mpb.RegisterMutationServiceServer(s, msrv)

	// Signer
	signer := sequencer.New(mapID, mapEnv.MapClient, logID, tlog, mutator, mutations, factory)

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%v) = %v", addr, err)
	}
	client := grpcc.New(cc, vrfPub, mapPubKey, coniks.Default, fake.NewFakeTrillianLogVerifier())
	client.RetryCount = 0

	// Mimic first sequence event
	if err := signer.Initialize(ctx); err != nil {
		t.Fatalf("signer.Initialize() = %v", err)
	}
	if err := signer.CreateEpoch(ctx, true); err != nil {
		t.Fatalf("CreateEpoch(_): %v", err)
	}

	return &Env{
		mapEnv:     mapEnv,
		GRPCServer: s,
		V2Server:   server,
		Conn:       cc,
		Client:     client,
		Signer:     signer,
		db:         sqldb,
		Factory:    factory,
		VrfPriv:    vrfPriv,
		Cli:        pb.NewKeyTransparencyServiceClient(cc),
	}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close(t *testing.T) {
	env.Conn.Close()
	env.GRPCServer.Stop()
	env.mapEnv.Close()
	env.db.Close()
}

// GetNewOutgoingContextWithFakeAuth returns a new context containing FakeAuth information to authenticate userID
func GetNewOutgoingContextWithFakeAuth(userID string) context.Context {
	md, _ := authentication.GetFakeCredential(userID).GetRequestMetadata(context.Background())
	return metadata.NewOutgoingContext(context.Background(), metadata.New(md))
}
