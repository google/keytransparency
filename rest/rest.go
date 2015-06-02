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

// Package rest converts REST HTTP requests into gRPC requests.
package rest

import (
	"log"
	"net"
	"net/http"

	"github.com/gdbelvin/key-server-transparency/proxy"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"

	context "golang.org/x/net/context"
)

const (
	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	DELETE = "DELETE"
)

// Server holds internal state for the http rest server.
type Server struct {
	*grpc.Server
	// TODO: hkp server api here.
	proxy *proxy.Server // v1 API.
	// TODO: v2 api server here.
	//creds Authenticator  // TODO define interface.
	rtr *mux.Router
}

// New creates a new rest server
// TODO(insert authenitcator as field param here
func New(proxy *proxy.Server) *Server {
	return &Server{grpc.NewServer(), proxy, mux.NewRouter()}
}

// Serve starts the server loop.
func (s *Server) Serve(l net.Listener) {
	log.Fatal(http.Serve(l, nil))
}

// Method is the function type for http handlers. Context will contain security
// info. Input will be supplied via the appropriate procol buffer, and response
// will also be provided via a protocol buffer.
type Handler func(interface{}, context.Context, http.ResponseWriter, *http.Request)

// AddHandler tels the server to route request with path and method to m.
func (s *Server) AddHandler(path string, method string, h Handler) {
	s.rtr.HandleFunc(path, s.handle(h)).Methods(method)
}

func (s *Server) handle(h Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build context.
		ctx := context.Background()
		// TODO insert authentication information.

		h(s.proxy, ctx, w, r)
	}
}
