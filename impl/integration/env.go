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
	"math/rand"
	"net"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/client/grpcc"
	"github.com/google/keytransparency/core/crypto/vrf/p256"
	"github.com/google/keytransparency/core/fake"
	"github.com/google/keytransparency/core/integration"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"

	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/sql/domain"
	"github.com/google/keytransparency/impl/sql/mutationstorage"

	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/merkle/coniks"
	"github.com/google/trillian/storage/testdb"

	"google.golang.org/grpc"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_proto"
	domaindef "github.com/google/keytransparency/core/domain"
	_ "github.com/google/trillian/merkle/coniks"    // Register hasher
	_ "github.com/google/trillian/merkle/objhasher" // Register hasher
	maptest "github.com/google/trillian/testonly/integration"
	_ "github.com/mattn/go-sqlite3" // Use sqlite database for testing.
)

// Listen opens a random local port and listens on it.
func Listen() (string, net.Listener, error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return "", nil, fmt.Errorf("failed to listen: %v", err)
	}
	_, port, err := net.SplitHostPort(lis.Addr().String())
	if err != nil {
		return "", nil, fmt.Errorf("Failed to parse listener address: %v", err)
	}
	addr := "localhost:" + port
	return addr, lis, nil
}

// Env holds a complete testing environment for end-to-end tests.
type Env struct {
	*integration.Env
	mapEnv     *maptest.MapEnv
	grpcServer *grpc.Server
	grpcCC     *grpc.ClientConn
	db         *sql.DB
}

func vrfKeyGen(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
	return der.NewProtoFromSpec(spec)
}

// NewEnv sets up common resources for tests.
func NewEnv() (*Env, error) {
	ctx := context.Background()
	domainID := fmt.Sprintf("domain %d", rand.Int()) // nolint: gas
	db, err := testdb.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("env: failed to open database: %v", err)
	}

	// Map server
	mapEnv, err := maptest.NewMapEnv(ctx)
	if err != nil {
		return nil, fmt.Errorf("env: failed to create trillian map server: %v", err)
	}

	// Configure domain, which creates new map and log trees.
	domainStorage, err := domain.NewStorage(db)
	if err != nil {
		return nil, fmt.Errorf("env: failed to create domain storage: %v", err)
	}
	adminSvr := adminserver.New(domainStorage, mapEnv.Map, mapEnv.Admin, mapEnv.Admin, vrfKeyGen)
	domainPB, err := adminSvr.CreateDomain(ctx, &pb.CreateDomainRequest{
		DomainId:    domainID,
		MinInterval: ptypes.DurationProto(1 * time.Second),
		MaxInterval: ptypes.DurationProto(5 * time.Second),
	})
	if err != nil {
		return nil, fmt.Errorf("env: CreateDomain(): %v", err)
	}

	mapID := domainPB.Map.TreeId
	logID := domainPB.Log.TreeId
	mapPubKey, err := der.UnmarshalPublicKey(domainPB.Map.GetPublicKey().GetDer())
	if err != nil {
		return nil, fmt.Errorf("env: Failed to load signing keypair: %v", err)
	}
	vrfPub, err := p256.NewVRFVerifierFromRawKey(domainPB.Vrf.GetDer())
	if err != nil {
		return nil, fmt.Errorf("env: Failed to load vrf pubkey: %v", err)
	}

	// Common data structures.
	mutations, err := mutationstorage.New(db)
	if err != nil {
		return nil, fmt.Errorf("env: Failed to create mutations object: %v", err)
	}
	auth := authentication.NewFake()
	authz := authorization.New()
	tlog := fake.NewTrillianLogClient()

	queue := mutator.MutationQueue(mutations)
	server := keyserver.New(tlog, mapEnv.Map, mapEnv.Admin,
		entry.New(), auth, authz, domainStorage, queue, mutations)
	gsvr := grpc.NewServer()
	pb.RegisterKeyTransparencyServer(gsvr, server)

	// Sequencer
	seq := sequencer.New(tlog, mapEnv.Map, entry.New(), domainStorage, mutations, queue)
	// Only sequence when explicitly asked with receiver.Flush()
	d := &domaindef.Domain{
		DomainID: domainID,
		LogID:    logID,
		MapID:    mapID,
	}
	receiver := seq.NewReceiver(ctx, d, 60*time.Hour, 60*time.Hour)
	receiver.Flush(ctx)

	addr, lis, err := Listen()
	if err != nil {
		return nil, err
	}
	go gsvr.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, fmt.Errorf("Dial(%v) = %v", addr, err)
	}
	ktClient := pb.NewKeyTransparencyClient(cc)
	client := grpcc.New(ktClient, domainID, vrfPub, mapPubKey, coniks.Default, fake.NewFakeTrillianLogVerifier())
	client.RetryCount = 0

	return &Env{
		Env: &integration.Env{
			Client:   client,
			Cli:      ktClient,
			Domain:   domainPB,
			Receiver: receiver,
		},
		mapEnv:     mapEnv,
		grpcServer: gsvr,
		grpcCC:     cc,
		db:         db,
	}, nil
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	env.grpcCC.Close()
	env.grpcServer.Stop()
	env.mapEnv.Close()
	env.db.Close()
}
