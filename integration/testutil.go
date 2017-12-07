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
	"context"
	"database/sql"
	"fmt"
	"log"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/client/grpcc"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutationserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/sql/adminstorage"
	"github.com/google/keytransparency/impl/sql/mutationstorage"
	"github.com/google/keytransparency/impl/transaction"

	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/storage/testdb"
	"github.com/google/trillian/testonly/integration"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	gpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
	_ "github.com/google/trillian/merkle/coniks"    // Register hasher
	_ "github.com/google/trillian/merkle/objhasher" // Register hasher
	_ "github.com/mattn/go-sqlite3"                 // Use sqlite database for testing.
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
	lis, err := net.Listen("tcp", "localhost:0")
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
	Cli        gpb.KeyTransparencyServiceClient
	Domain     *pb.Domain
}

func vrfKeyGen(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
	return der.NewProtoFromSpec(spec)
}

// NewEnv sets up common resources for tests.
func NewEnv(t *testing.T) *Env {
	ctx := context.Background()
	domainID := fmt.Sprintf("domain %d", rand.Int()) // nolint: gas
	sqldb := NewDB(t)

	// We can only run the integration tests if there is a MySQL instance available.
	if provider := testdb.Default(); !provider.IsMySQL() {
		t.Skipf("Skipping map integration test, SQL driver is %v", provider.Driver)
	}

	// Map server
	mapEnv, err := integration.NewMapEnv(ctx)
	if err != nil {
		t.Fatalf("Failed to create trillian map server: %v", err)
	}

	// Configure domain, which creates new map and log trees.
	adminStorage, err := adminstorage.New(sqldb)
	if err != nil {
		t.Fatalf("Failed to create admin storage: %v", err)
	}
	adminSvr := adminserver.New(adminStorage, mapEnv.AdminClient, mapEnv.AdminClient, vrfKeyGen)
	resp, err := adminSvr.CreateDomain(ctx, &pb.CreateDomainRequest{
		DomainId:    domainID,
		MinInterval: ptypes.DurationProto(1 * time.Second),
		MaxInterval: ptypes.DurationProto(5 * time.Second),
	})
	if err != nil {
		t.Fatalf("CreateDomain(): %v", err)
	}

	mapID := resp.Domain.Map.TreeId
	logID := resp.Domain.Log.TreeId
	mapPubKey, err := der.UnmarshalPublicKey(resp.Domain.Map.GetPublicKey().GetDer())
	if err != nil {
		t.Fatalf("Failed to load signing keypair: %v", err)
	}
	vrfPub, err := p256.NewVRFVerifierFromRawKey(resp.Domain.Vrf.GetDer())
	if err != nil {
		t.Fatalf("Failed to load vrf pubkey: %v", err)
	}

	// Common data structures.
	mutations, err := mutationstorage.New(sqldb)
	if err != nil {
		log.Fatalf("Failed to create mutations object: %v", err)
	}
	mutator := entry.New()
	auth := authentication.NewFake()
	authz := authorization.New()
	tlog := fake.NewTrillianLogClient()

	factory := transaction.NewFactory(sqldb)
	server := keyserver.New(adminStorage, tlog, mapEnv.MapClient, mapEnv.AdminClient,
		mutator, auth, authz, factory, mutations)
	gsvr := grpc.NewServer()
	msrv := mutationserver.New(adminStorage, tlog, mapEnv.MapClient, mutations, factory)
	gpb.RegisterKeyTransparencyServiceServer(gsvr, server)
	gpb.RegisterMutationServiceServer(gsvr, msrv)

	// Sequencer
	seq := sequencer.New(adminStorage, mapEnv.MapClient, tlog, mutator, mutations, factory)

	addr, lis := Listen(t)
	go gsvr.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%v) = %v", addr, err)
	}
	client := grpcc.New(cc, domainID, vrfPub, mapPubKey, coniks.Default, fake.NewFakeTrillianLogVerifier())
	client.RetryCount = 0

	// Mimic first sequence event
	if err := seq.Initialize(ctx, logID, mapID); err != nil {
		t.Fatalf("seq.Initialize() = %v", err)
	}
	if err := seq.CreateEpoch(ctx, logID, mapID, sequencer.ForceNewEpoch(true)); err != nil {
		t.Fatalf("CreateEpoch(_): %v", err)
	}

	return &Env{
		mapEnv:     mapEnv,
		GRPCServer: gsvr,
		V2Server:   server,
		Conn:       cc,
		Client:     client,
		Signer:     seq,
		db:         sqldb,
		Factory:    factory,
		Cli:        gpb.NewKeyTransparencyServiceClient(cc),
		Domain:     resp.Domain,
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
