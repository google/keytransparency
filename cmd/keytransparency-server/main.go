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
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/go-kit/kit/log"
	"github.com/golang/glog"
	"github.com/google/trillian"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/kit"
	"gocloud.dev/server"
	"gocloud.dev/server/health"
	"golang.org/x/sync/errgroup"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	"github.com/google/keytransparency/cmd/serverutil"
	"github.com/google/keytransparency/core/keyserver"
	"github.com/google/keytransparency/core/mutator/entry"
	"github.com/google/keytransparency/impl"
	"github.com/google/keytransparency/impl/authentication"
	"github.com/google/keytransparency/impl/authorization"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"

	_ "github.com/google/trillian/crypto/keys/der/proto"
)

var (
	addr        = flag.String("addr", ":8080", "The ip:port combination to listen on")
	metricsAddr = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")
	dbPath      = flag.String("db", "test:zaphod@tcp(localhost:3306)/test", "Database connection string")
	dbEngine    = flag.String("db_engine", "mysql", fmt.Sprintf("Storage engines: %v", impl.StorageEngines()))
	keyFile     = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile    = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")
	authType    = flag.String("auth-type", "google", "Sets the type of authentication required from clients to update their entries. Accepted values are google (oauth tokens) and insecure-fake (for testing only).")

	mapURL           = flag.String("map-url", "", "URL of Trillian Map Server")
	logURL           = flag.String("log-url", "", "URL of Trillian Log Server for Signed Map Heads")
	revisionPageSize = flag.Int("revision-page-size", 10, "Max number of revisions to return at once")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	// Open Resources.
	db, err := impl.NewStorage(ctx, *dbEngine, *dbPath)
	if err != nil {
		glog.Exit(err)
	}
	defer db.Close()

	authz := &authorization.AuthzPolicy{}
	var authFunc grpc_auth.AuthFunc
	switch *authType {
	case "insecure-fake":
		glog.Warning("INSECURE! Using fake authentication.")
		authFunc = authentication.FakeAuthFunc
	case "google":
		var err error
		gauth, err := authentication.NewGoogleAuth(ctx)
		if err != nil {
			glog.Exitf("Failed to create authentication library instance: %v", err)
		}
		authFunc = gauth.AuthFunc
	default:
		glog.Exitf("Invalid auth-type parameter: %v.", *authType)
	}

	// Connect to log and map server.
	tconn, err := grpc.Dial(*logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *logURL, err)
	}
	mconn, err := grpc.Dial(*mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	tlog := trillian.NewTrillianLogClient(tconn)
	tmap := trillian.NewTrillianMapClient(mconn)

	// Create gRPC server.
	ksvr := keyserver.New(tlog, tmap, entry.IsValidEntry, db.Directories, db.Logs, db.Batches,
		prometheus.MetricFactory{}, int32(*revisionPageSize))

	logger := log.NewLogfmtLogger(os.Stdout)
	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpc_middleware.ChainStreamServer(
			grpc_prometheus.StreamServerInterceptor,
			kit.StreamServerInterceptor(logger),
			authorization.StreamServerInterceptor(map[string]authorization.AuthPair{
				// All streaming methods are unauthenticated for now.
			}),
		)),
		grpc.UnaryInterceptor(grpc_middleware.ChainUnaryServer(
			grpc_prometheus.UnaryServerInterceptor,
			kit.UnaryServerInterceptor(logger),
			authorization.UnaryServerInterceptor(map[string]authorization.AuthPair{
				"/google.keytransparency.v1.KeyTransparency/UpdateEntry": {
					AuthnFunc: authFunc,
					AuthzFunc: authz.Authorize,
				},
			}),
		)),
	)
	pb.RegisterKeyTransparencyServer(grpcServer, ksvr)
	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	lis, conn, done, err := serverutil.ListenTLS(ctx, *addr, *certFile, *keyFile)
	if err != nil {
		glog.Fatalf("Listen(%v): %v", *addr, err)
	}
	defer done()

	metricsSvr := serverutil.MetricsServer(*metricsAddr, &server.Options{
		HealthChecks: []health.Checker{db.HealthChecker},
	})
	grpcGatewaySvr, err := serverutil.GRPCGatewayServer(ctx, grpcServer, conn,
		pb.RegisterKeyTransparencyHandler)
	if err != nil {
		glog.Fatalf("GrpcGatewayServer(): %v", err)
	}

	g, _ := errgroup.WithContext(ctx)
	g.Go(func() error { return metricsSvr.ListenAndServe(*metricsAddr) })
	g.Go(func() error { return grpcGatewaySvr.Serve(lis) })
	go serverutil.ListenForCtrlC(metricsSvr, grpcGatewaySvr)

	glog.Errorf("Key Transparency Server exiting: %v", g.Wait())
}
