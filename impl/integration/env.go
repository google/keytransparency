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
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto" //nolint:staticcheck
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/any"
	"github.com/kr/pretty"
	"google.golang.org/grpc"

	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/client"
	"github.com/google/keytransparency/core/client/tracker"
	"github.com/google/keytransparency/core/client/verifier"
	"github.com/google/keytransparency/core/integration"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/keytransparency/impl/authorization"
	"github.com/google/keytransparency/impl/mysql/directory"
	"github.com/google/keytransparency/impl/mysql/mutationstorage"
	"github.com/google/keytransparency/impl/mysql/testdb"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/monitoring"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	tclient "github.com/google/trillian/client"
	ttest "github.com/google/trillian/testonly/integration"

	_ "github.com/google/trillian/merkle/coniks"  // Register hasher
	_ "github.com/google/trillian/merkle/rfc6962" // Register hasher
)

var (
	// openssl ecparam -name prime256v1 -genkey
	vrfPriv = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEINS30QIDiMV1Npc8/J4OVGcHdSJTsiHhUx9rsK+OdLh2oAoGCCqGSM49
AwEHoUQDQgAEF2Pm2kKya+JBun1QRmKQMcoMOIBNWp8fjECkJX+/hNWdV1UKb12W
+yXcX2MqN7ZMX77hS9mLus/WaE0NS370mA==
-----END EC PRIVATE KEY-----`
	logPriv = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIH7vjXeafneG0+7UxF1YGi4Env2L5LLnhqhfcwZafirMoAoGCCqGSM49
AwEHoUQDQgAEqGXPnhMIclRmYHSmAnCMmfDUJ9iNBMmFxR/wHJdL12AuVUkgcuhb
Ep2hy5ETs7bfFc2P95IYFlmbiuHMq3UY/A==
-----END EC PRIVATE KEY-----`
	mapPriv = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIC4FhRijqobFJXcyojcPZX88sDtHgzp5ydmSgv1PqIlvoAoGCCqGSM49
AwEHoUQDQgAEWLHm0TLYaTzENpPkBl2E79ySqJI+EW51VpoWh7wqY3OjSJcft4zg
EeNeHYEb/T2jBFH4eYg4iSN7D/VYaJxJRA==
-----END EC PRIVATE KEY-----`
)

// Listen opens a random local port and listens on it.
func Listen() (net.Listener, *grpc.ClientConn, error) {
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen: %v", err)
	}
	addr := lis.Addr().String()
	conn, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("error connecting to %v: %v", addr, err)
	}
	return lis, conn, nil
}

// Env holds a complete testing environment for end-to-end tests.
type Env struct {
	*integration.Env
	mapEnv     *ttest.MapEnv
	logEnv     *ttest.LogEnv
	admin      *adminserver.Server
	grpcServer *grpc.Server
	grpcCC     *grpc.ClientConn
	db         *sql.DB
}

func vrfKeyGen(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
	return der.NewProtoFromSpec(spec)
}

func keyFromPEM(p string) *any.Any {
	block, _ := pem.Decode([]byte(p))
	k := &keyspb.PrivateKey{Der: block.Bytes}
	a, err := ptypes.MarshalAny(k)
	if err != nil {
		panic("MarshalAny failed")
	}
	return a
}

// NewEnv sets up common resources for tests.
func NewEnv(ctx context.Context, t testing.TB) *Env {
	t.Helper()
	timeout := 6 * time.Second
	directoryID := "integration"

	db := testdb.NewForTest(ctx, t)

	// Map server
	mapEnv, err := ttest.NewMapEnv(ctx, false)
	if err != nil {
		t.Fatalf("env: failed to create trillian map server: %v", err)
	}

	// Log server
	numSequencers := 1
	unused := ""
	logEnv, err := ttest.NewLogEnv(ctx, numSequencers, unused)
	if err != nil {
		t.Fatalf("env: failed to create trillian log server: %v", err)
	}

	// Configure directory, which creates new map and log trees.
	directoryStorage, err := directory.NewStorage(db)
	if err != nil {
		t.Fatalf("env: failed to create directory storage: %v", err)
	}
	mutations, err := mutationstorage.New(db)
	if err != nil {
		t.Fatalf("env: Failed to create mutations object: %v", err)
	}
	adminSvr := adminserver.New(logEnv.Log, mapEnv.Map, logEnv.Admin, mapEnv.Admin, directoryStorage, mutations, mutations, vrfKeyGen)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	directoryPB, err := adminSvr.CreateDirectory(cctx, &pb.CreateDirectoryRequest{
		DirectoryId:   directoryID,
		MinInterval:   ptypes.DurationProto(100 * time.Millisecond),
		MaxInterval:   ptypes.DurationProto(60 * time.Hour),
		VrfPrivateKey: keyFromPEM(vrfPriv),
		LogPrivateKey: keyFromPEM(logPriv),
		MapPrivateKey: keyFromPEM(mapPriv),
	})
	if err != nil {
		t.Fatalf("env: CreateDirectory(): %v", err)
	}
	glog.V(5).Infof("Directory: %# v", pretty.Formatter(directoryPB))

	// Common data structures.
	authz := &authorization.AuthzPolicy{}

	lis, cc, err := Listen()
	if err != nil {
		t.Fatalf("env: Listen(): %v", err)
	}

	gsvr := grpc.NewServer(
		grpc.UnaryInterceptor(
			authorization.UnaryServerInterceptor(map[string]authorization.AuthPair{
				"/google.keytransparency.v1.KeyTransparency/UpdateEntry": {
					AuthnFunc: authentication.FakeAuthFunc,
					AuthzFunc: authz.Authorize,
				},
			}),
		),
	)

	pb.RegisterKeyTransparencyServer(gsvr, keyserver.New(
		logEnv.Log, mapEnv.Map,
		entry.IsValidEntry, directoryStorage,
		mutations, mutations,
		monitoring.InertMetricFactory{},
		10, /*Revisions per page */
	))

	spb.RegisterKeyTransparencySequencerServer(gsvr, sequencer.NewServer(
		directoryStorage,
		logEnv.Log, mapEnv.Map, mapEnv.Write,
		mutations, mutations,
		spb.NewKeyTransparencySequencerClient(cc),
		monitoring.InertMetricFactory{},
	))

	go gsvr.Serve(lis)

	ktClient := pb.NewKeyTransparencyClient(cc)
	client, err := client.NewFromConfig(ktClient, directoryPB,
		func(lv *tclient.LogVerifier) verifier.LogTracker { return tracker.NewSynchronous(lv) },
	)
	if err != nil {
		t.Fatalf("error reading config: %v", err)
	}
	// Integration tests manually create revisions immediately, so retry fairly quickly.
	client.RetryDelay = 10 * time.Millisecond
	return &Env{
		Env: &integration.Env{
			Client:    client,
			Cli:       pb.NewKeyTransparencyClient(cc),
			Sequencer: spb.NewKeyTransparencySequencerClient(cc),
			Directory: directoryPB,
			Timeout:   timeout,
			CallOpts: func(userID string) []grpc.CallOption {
				return []grpc.CallOption{grpc.PerRPCCredentials(authentication.GetFakeCredential(userID))}
			},
		},
		mapEnv:     mapEnv,
		logEnv:     logEnv,
		admin:      adminSvr,
		grpcServer: gsvr,
		grpcCC:     cc,
		db:         db,
	}
}

// Close releases resources allocated by NewEnv.
func (env *Env) Close() {
	ctx := context.Background()
	if _, err := env.admin.DeleteDirectory(ctx, &pb.DeleteDirectoryRequest{
		DirectoryId: env.Directory.DirectoryId,
	}); err != nil {
		glog.Errorf("env: Close(): DeleteDirectory(%v): %v", env.Directory.DirectoryId, err)
	}
	env.grpcCC.Close()
	env.grpcServer.Stop()
	env.mapEnv.Close()
	env.logEnv.Close()
	env.db.Close()
}
