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
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/e2e-key-server/appender"
	"github.com/google/e2e-key-server/client"
	"github.com/google/e2e-key-server/commitments"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/mutator/entry"
	"github.com/google/e2e-key-server/queue"
	"github.com/google/e2e-key-server/signer"
	"github.com/google/e2e-key-server/tree/sparse/sqlhist"
	"github.com/google/e2e-key-server/vrf"
	"github.com/google/e2e-key-server/vrf/p256"

	"github.com/coreos/etcd/integration"
	_ "github.com/mattn/go-sqlite3"
	"google.golang.org/grpc"

	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

const (
	clusterSize      = 1
	mapID            = "testID"
	ValidSTHResponse = `{"tree_size":3721782,"timestamp":1396609800587,
        "sha256_root_hash":"SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo=",
        "tree_head_signature":"BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="}`
	ValidSTHResponseTreeSize          = 3721782
	ValidSTHResponseTimestamp         = 1396609800587
	ValidSTHResponseSHA256RootHash    = "SxKOxksguvHPyUaKYKXoZHzXl91Q257+JQ0AUMlFfeo="
	ValidSTHResponseTreeHeadSignature = "BAMARjBEAiBUYO2tODlUUw4oWGiVPUHqZadRRyXs9T2rSXchA79VsQIgLASkQv3cu4XdPFCZbgFkIUefniNPCpO3LzzHX53l+wg="
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
	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ct/v1/get-sth" {
			fmt.Fprintf(w, `{"tree_size": %d, "timestamp": %d, "sha256_root_hash": "%s", "tree_head_signature": "%s"}`,
				ValidSTHResponseTreeSize, int64(ValidSTHResponseTimestamp), ValidSTHResponseSHA256RootHash,
				ValidSTHResponseTreeHeadSignature)
			return
		} else if r.URL.Path == "/ct/v1/add-json" {
			w.Write([]byte(`{"sct_version":0,"id":"KHYaGJAn++880NYaAY12sFBXKcenQRvMvfYE9F1CYVM=","timestamp":1337,"extensions":"","signature":"BAMARjBEAiAIc21J5ZbdKZHw5wLxCP+MhBEsV5+nfvGyakOIv6FOvAIgWYMZb6Pw///uiNM7QTg2Of1OqmK1GbeGuEl9VJN8v8c="}`))
			return
		}
		t.Fatalf("Incorrect URL path: %s", r.URL.Path)
	}))

	/*
		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	*/
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

	signer := signer.New(queue, tree, mutator, appender)
	signer.CreateEpoch()

	addr, lis := Listen(t)
	go s.Serve(lis)

	// Client
	cc, err := grpc.Dial(addr, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("Dial(%q) = %v", addr, err)
	}
	cli := v2pb.NewE2EKeyServiceClient(cc)
	client := client.New(cli, vrfPub, hs.URL)
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
