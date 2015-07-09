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
)

// Struct containing routes info
type RouteInfo struct {
	Method      string
	Initializer handlers.InitializeHandlerInfo
	Handler     handlers.RequestHandler
}

var port = flag.Int("port", 8080, "TCP port to listen on")

// Map containing all routes information
// TODO: find a better way to populate this map
var v1Routes = map[string]RouteInfo{
	"/v1/user/{userid}": RouteInfo{
		"GET",
		rest.GetUser_InitializeHandlerInfo,
		rest.GetUser_RequestHandler,
	},
}

func main() {
	flag.Parse()

	portString := fmt.Sprintf(":%d", *port)
	// TODO: fetch private TLS key from repository
	lis, err := net.Listen("tcp", portString)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	v2 := keyserver.Create(storage.CreateMem(context.Background()))
	v1 := proxy.New(v2)
	s := rest.New(v1)

	// Manually add routing paths.
	// TODO: Auto derive from proto.
	for k, v := range v1Routes {
		s.AddHandler(k, v.Method, v1pb.Handler, v.Initializer, v.Handler)
	}
	// TODO: add hkp server api here.

	s.Serve(lis)
}
