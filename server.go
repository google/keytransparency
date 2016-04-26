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
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/e2e-key-server/appender/chain"
	"github.com/google/e2e-key-server/db/commitments"
	"github.com/google/e2e-key-server/db/memdb"
	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/mutator/entry"
	"github.com/google/e2e-key-server/proxy"
	"github.com/google/e2e-key-server/rest"
	"github.com/google/e2e-key-server/rest/handlers"
	"github.com/google/e2e-key-server/signer"
	"github.com/google/e2e-key-server/tree/sparse/sqlhist"

	_ "github.com/mattn/go-sqlite3"

	v1pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
	v2pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v2"
)

var (
	// Read port flag.
	port = flag.Int("port", 8080, "TCP port to listen on")
	// Read AuthenticationRealm flag.
	realm = flag.String("auth-realm", "registered-users@gmail.com", "Authentication realm for WWW-Authenticate response header")
	// Read server DB path flag.
	serverDBPath = flag.String("server-db-path", "db", "path/to/server/db where the local database will be created/opened.")
	// Read epoch advancement duration flag.
	epochDuration = flag.Uint("epoch-duration", 60, "Epoch advancement duration")
	mapID         = flag.String("mapID", "domain", "Domain for user identifiers.")
)

// v1Routes contains all routes information for v1 APIs.
// TODO(cesarghali): find a better way to populate this map.
var v1Routes = []handlers.RouteInfo{
	// GetEntry API
	handlers.RouteInfo{
		fmt.Sprintf("/v1/users/{%v}", handlers.UserIdKeyword),
		"GET",
		rest.GetEntryV1_InitializeHandlerInfo,
		rest.GetEntryV1_RequestHandler,
	},
}

// hkpRoutes contains all routes information for HKP APIs.
// TODO(cesarghali): find a better way to populate this map.
var hkpRoutes = []handlers.RouteInfo{
	// HkpLookup API
	handlers.RouteInfo{
		"/v1/hkp/lookup",
		"GET",
		rest.HkpLookup_InitializeHandlerInfo,
		rest.HkpLookup_RequestHandler,
	},
}

// v2Routes contains all routes information for v2 APIs.
// TODO(cesarghali): find a better way to populate this map.
var v2Routes = []handlers.RouteInfo{
	// GetEntry API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}", handlers.UserIdKeyword),
		"GET",
		rest.GetEntryV2_InitializeHandlerInfo,
		rest.GetEntryV2_RequestHandler,
	},
	// ListEntryHistory API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}/history", handlers.UserIdKeyword),
		"GET",
		rest.ListEntryHistoryV2_InitializeHandlerInfo,
		rest.ListEntryHistoryV2_RequestHandler,
	},
	// UpdateEntry API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}", handlers.UserIdKeyword),
		"PUT",
		rest.UpdateEntryV2_InitializeHandlerInfo,
		rest.UpdateEntryV2_RequestHandler,
	},
	// ListSEH API
	handlers.RouteInfo{
		"/v2/seh",
		"GET",
		rest.ListSEHV2_InitializeHandlerInfo,
		rest.ListSEHV2_RequestHandler,
	},
	// ListUpdate API
	handlers.RouteInfo{
		"/v2/update",
		"GET",
		rest.ListUpdateV2_InitializeHandlerInfo,
		rest.ListUpdateV2_RequestHandler,
	},
	// ListSteps API
	handlers.RouteInfo{
		"/v2/step",
		"GET",
		rest.ListStepsV2_InitializeHandlerInfo,
		rest.ListStepsV2_RequestHandler,
	},
}

func openDB() *sql.DB {
	db, err := sql.Open("sqlite3", *serverDBPath)
	if err != nil {
		log.Fatalf("sql.Open(): %v", err)
	}
	if err := db.Ping(); err != nil {
		log.Fatalf("db.Ping(): %v", err)
	}
	return db
}

func main() {
	flag.Parse()

	// TODO: fetch private TLS key from repository.
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	// Create a memory storage.
	db := memdb.New()
	mutator := entry.New()
	appender := chain.New()

	sqldb := openDB()
	defer sqldb.Close()
	tree := sqlhist.New(sqldb, *mapID)
	commitments := commitments.New(sqldb, *mapID)
	// Create a signer.
	signer, err := signer.New(db, tree, mutator, appender)
	signer.StartSequencing()
	signer.StartSigning(time.Duration(*epochDuration) * time.Second)
	if err != nil {
		log.Fatalf("Cannot create a signer instance: (%v)\nExisting the server.\n", err)
		return
	}
	defer signer.Stop()
	// Create the servers.
	v2 := keyserver.New(commitments, db, tree, appender)
	v1 := proxy.New(v2)
	s := rest.New(v1, *realm)

	// Manually add routing paths for v1 APIs.
	// TODO: Auto derive from proto.
	for _, v := range v1Routes {
		s.AddHandler(v, v1pb.HandlerV1, v1)
	}
	// Manually add routing paths for HKP APIs.
	// TODO: Auto derive from proto.
	for _, v := range hkpRoutes {
		s.AddHandler(v, v1pb.HandlerHkp, v1)
	}
	// Manually add routing paths for v2 APIs.
	// TODO: Auto derive from proto.
	for _, v := range v2Routes {
		s.AddHandler(v, v2pb.HandlerV2, v2)
	}

	s.Serve(lis)
}
