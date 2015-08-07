// Copyright 2015 Google Inc. All Rights Reserved.
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
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/e2e-key-server/keyserver"
	"github.com/google/e2e-key-server/proxy"
	"github.com/google/e2e-key-server/rest"
	"github.com/google/e2e-key-server/rest/handlers"
	"github.com/google/e2e-key-server/storage"
	"golang.org/x/net/context"

	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

var port = flag.Int("port", 8080, "TCP port to listen on")

// v1Routes contains all routes information for v1 APIs.
// TODO(cesarghali): find a better way to populate this map.
var v1Routes = []handlers.RouteInfo{
	// GetUser API
	handlers.RouteInfo{
		fmt.Sprintf("/v1/users/{%v}", handlers.USER_ID_KEYWORD),
		"GET",
		rest.GetUserV1_InitializeHandlerInfo,
		rest.GetUserV1_RequestHandler,
	},
}

// v2Routes contains all routes information for v2 APIs.
// TODO(cesarghali): find a better way to populate this map.
var v2Routes = []handlers.RouteInfo{
	// GetUser API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}", handlers.USER_ID_KEYWORD),
		"GET",
		rest.GetUserV2_InitializeHandlerInfo,
		rest.GetUserV2_RequestHandler,
	},
	// ListUserHistory API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}/history", handlers.USER_ID_KEYWORD),
		"GET",
		rest.ListUserHistoryV2_InitializeHandlerInfo,
		rest.ListUserHistoryV2_RequestHandler,
	},
	// UpdateUser API
	handlers.RouteInfo{
		fmt.Sprintf("/v2/users/{%v}", handlers.USER_ID_KEYWORD),
		"PUT",
		rest.UpdateUserV2_InitializeHandlerInfo,
		rest.UpdateUserV2_RequestHandler,
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

func main() {
	flag.Parse()

	portString := fmt.Sprintf(":%d", *port)
	// TODO: fetch private TLS key from repository.
	lis, err := net.Listen("tcp", portString)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	v2 := keyserver.Create(storage.CreateMem(context.Background()))
	v1 := proxy.New(v2)
	s := rest.New(v1)

	// Manually add routing paths for v1 APIs.
	// TODO: Auto derive from proto.
	for _, v := range v1Routes {
		s.AddHandler(v, v1pb.Handler, v1)
	}
	// Manually add routing paths for v2 APIs.
	// TODO: Auto derive from proto.
	for _, v := range v2Routes {
		s.AddHandler(v, v2pb.Handler, v2)
	}
	// TODO: add hkp server api here.

	s.Serve(lis)
}
