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

var port = flag.Int("port", 8080, "TCP port to listen on")

// Map containing all routes information.
// TODO(cesarghali): find a better way to populate this map.
var v1Routes = map[string]handlers.RouteInfo{
	"/v1/users/{userid}": handlers.RouteInfo{
		"/v1/users/{userid}",
		2,
		-1, // No keyId in the path.
		"GET",
		rest.GetUser_InitializeHandlerInfo,
		rest.GetUser_RequestHandler,
	},
	"/v1/users/{userid}/keys": handlers.RouteInfo{
		"/v1/users/{userid}/keys",
		2,
		-1, // No keyId in the path.
		"POST",
		rest.CreateKey_InitializeHandlerInfo,
		rest.CreateKey_RequestHandler,
	},
	"/v1/users/{userid}/keys/<keyid>": handlers.RouteInfo{
		"/v1/users/{userid}/keys/<keyid>",
		2,
		4,
		"PUT",
		rest.UpdateKey_InitializeHandlerInfo,
		rest.UpdateKey_RequestHandler,
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

	// Manually add routing paths.
	// TODO: Auto derive from proto.
	for _, v := range v1Routes {
		s.AddHandler(v, v1pb.Handler)
	}
	// TODO: add hkp server api here.

	s.Serve(lis)
}
