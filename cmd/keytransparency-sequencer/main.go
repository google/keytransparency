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
	"database/sql"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/golang/glog"
	"github.com/golang/protobuf/proto"
	"github.com/google/trillian"
	"github.com/google/trillian/crypto/keys/der"
	"github.com/google/trillian/crypto/keyspb"
	"github.com/google/trillian/monitoring/prometheus"
	"github.com/google/trillian/util/election2"
	"github.com/google/trillian/util/etcd"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/reflection"

	"github.com/google/keytransparency/core/adminserver"
	"github.com/google/keytransparency/core/sequencer"
	"github.com/google/keytransparency/core/sequencer/election"
	"github.com/google/keytransparency/impl/sql/directory"
	"github.com/google/keytransparency/impl/sql/engine"
	"github.com/google/keytransparency/impl/sql/mutationstorage"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
	dir "github.com/google/keytransparency/core/directory"
	spb "github.com/google/keytransparency/core/sequencer/sequencer_go_proto"
	etcdelect "github.com/google/trillian/util/election2/etcd"
	grpc_prometheus "github.com/grpc-ecosystem/go-grpc-prometheus"

	_ "github.com/google/trillian/crypto/keys/der/proto"
	_ "github.com/google/trillian/merkle/coniks"  // Register hasher
	_ "github.com/google/trillian/merkle/rfc6962" // Register hasher
)

var (
	keyFile     = flag.String("tls-key", "genfiles/server.key", "TLS private key file")
	certFile    = flag.String("tls-cert", "genfiles/server.crt", "TLS cert file")
	listenAddr  = flag.String("addr", ":8080", "The ip:port to serve on")
	metricsAddr = flag.String("metrics-addr", ":8081", "The ip:port to publish metrics on")

	forceMaster = flag.Bool("force_master", false, "If true, assume master for all directories")
	etcdServers = flag.String("etcd_servers", "", "A comma-separated list of etcd servers; no etcd registration if empty")
	lockDir     = flag.String("lock_file_path", "/keytransparency/master", "etcd lock file directory path")

	serverDBPath = flag.String("db", "db", "Database connection string")

	// Info to connect to the trillian map and log.
	mapURL = flag.String("map-url", "", "URL of Trillian Map Server")
	logURL = flag.String("log-url", "", "URL of Trillian Log Server for Signed Map Heads")

	refresh   = flag.Duration("directory-refresh", 5*time.Second, "Time to detect new directory")
	batchSize = flag.Int("batch-size", 100, "Maximum number of mutations to process per map revision")
)

func openDB() *sql.DB {
	db, err := sql.Open(engine.DriverName, *serverDBPath)
	if err != nil {
		glog.Exitf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		glog.Exitf("db.Ping(): %v", err)
	}
	return db
}

// getElectionFactory returns an election factory based on flags, and a
// function which releases the resources associated with the factory.
func getElectionFactory() (election2.Factory, func()) {
	if *forceMaster {
		glog.Warning("Acting as master for all directories")
		return election2.NoopFactory{}, func() {}
	}
	if len(*etcdServers) == 0 {
		glog.Exit("Either --force_master or --etcd_servers must be supplied")
	}

	cli, err := etcd.NewClientFromString(*etcdServers)
	if err != nil || cli == nil {
		glog.Exitf("Failed to create etcd client: %v", err)
	}
	closeFn := func() {
		if err := cli.Close(); err != nil {
			glog.Warningf("etcd client Close(): %v", err)
		}
	}

	hostname, _ := os.Hostname()
	instanceID := fmt.Sprintf("%s.%d", hostname, os.Getpid())
	factory := etcdelect.NewFactory(instanceID, cli, *lockDir)

	return factory, closeFn
}

func main() {
	flag.Parse()
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Connect to trillian log and map backends.
	mconn, err := grpc.DialContext(ctx, *mapURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("grpc.Dial(%v): %v", *mapURL, err)
	}
	lconn, err := grpc.DialContext(ctx, *logURL, grpc.WithInsecure())
	if err != nil {
		glog.Exitf("Failed to connect to %v: %v", *logURL, err)
	}

	// Database tables
	sqldb := openDB()
	defer sqldb.Close()

	mutations, err := mutationstorage.New(sqldb)
	if err != nil {
		glog.Exitf("Failed to create mutations object: %v", err)
	}
	directoryStorage, err := directory.NewStorage(sqldb)
	if err != nil {
		glog.Exitf("Failed to create directory storage object: %v", err)
	}

	grpcServer := grpc.NewServer(
		grpc.StreamInterceptor(grpc_prometheus.StreamServerInterceptor),
		grpc.UnaryInterceptor(grpc_prometheus.UnaryServerInterceptor),
	)

	// Listen and create empty grpc client connection.
	lis, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		glog.Exitf("error creating TCP listener: %v", err)
	}
	glog.Infof("Listening on %v", lis.Addr().String())
	// Non-blocking dial before we start the server.
	tcreds, err := credentials.NewClientTLSFromFile(*certFile, "localhost")
	if err != nil {
		glog.Exitf("Failed opening cert file %v: %v", *certFile, err)
	}
	dopts := []grpc.DialOption{grpc.WithTransportCredentials(tcreds)}
	addr := lis.Addr().String()
	conn, err := grpc.DialContext(ctx, addr, dopts...)
	if err != nil {
		glog.Exitf("error connecting to %v: %v", addr, err)
	}
	defer conn.Close()

	spb.RegisterKeyTransparencySequencerServer(grpcServer, sequencer.NewServer(
		directoryStorage,
		trillian.NewTrillianLogClient(lconn),
		trillian.NewTrillianMapClient(mconn),
		trillian.NewTrillianMapWriteClient(mconn),
		mutations, mutations,
		spb.NewKeyTransparencySequencerClient(conn),
		prometheus.MetricFactory{}))

	pb.RegisterKeyTransparencyAdminServer(grpcServer, adminserver.New(
		trillian.NewTrillianLogClient(lconn),
		trillian.NewTrillianMapClient(mconn),
		trillian.NewTrillianAdminClient(lconn),
		trillian.NewTrillianAdminClient(mconn),
		directoryStorage,
		mutations,
		mutations,
		func(ctx context.Context, spec *keyspb.Specification) (proto.Message, error) {
			return der.NewProtoFromSpec(spec)
		}))

	reflection.Register(grpcServer)
	grpc_prometheus.Register(grpcServer)
	grpc_prometheus.EnableHandlingTimeHistogram()

	glog.Infof("Signer starting")

	// Run servers
	go serveHTTPMetric(*metricsAddr)
	go serveHTTPGateway(ctx, lis, dopts, grpcServer,
		pb.RegisterKeyTransparencyAdminHandlerFromEndpoint,
	)
	runSequencer(ctx, conn, directoryStorage)

	// Shutdown.
	glog.Errorf("Signer exiting")
}

func runSequencer(ctx context.Context, conn *grpc.ClientConn,
	directoryStorage dir.Storage) {
	electionFactory, closeFactory := getElectionFactory()
	defer closeFactory()
	signer := sequencer.New(
		spb.NewKeyTransparencySequencerClient(conn),
		directoryStorage,
		election.NewTracker(electionFactory, 1*time.Hour, prometheus.MetricFactory{}),
	)

	go signer.TrackMasterships(ctx)

	go sequencer.PeriodicallyRun(ctx, time.Tick(*refresh), func(ctx context.Context) {
		if err := signer.ForAllMasterships(ctx, func(ctx context.Context, dirID string) error {
			_, err := spb.NewKeyTransparencySequencerClient(conn).
				UpdateMetrics(ctx, &spb.UpdateMetricsRequest{
					DirectoryId:       dirID,
					MaxUnappliedCount: 100000,
				})
			return err
		}); err != nil {
			glog.Errorf("UpdateMetrics(): %v", err)
		}
	})

	if err := signer.AddAllDirectories(ctx); err != nil {
		glog.Errorf("runSequencer(AddAllDirectories): %v", err)
	}
	go sequencer.PeriodicallyRun(ctx, time.Tick(*refresh), func(ctx context.Context) {
		if err := signer.AddAllDirectories(ctx); err != nil {
			glog.Errorf("PeriodicallyRun(AddAllDirectories): %v", err)
		}
		if err := signer.RunBatchForAllMasterships(ctx, int32(*batchSize)); err != nil {
			glog.Errorf("PeriodicallyRun(RunBatchForAllMasterships): %v", err)
		}
	})

	sequencer.PeriodicallyRun(ctx, time.Tick(*refresh), func(ctx context.Context) {
		if err := signer.PublishLogForAllMasterships(ctx); err != nil {
			glog.Errorf("PeriodicallyRun(PublishRevisionsForAllMasterships): %v", err)
		}
	})
}
