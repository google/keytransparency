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

// Package rest converts REST HTTP requests into function calls.
package rest

import (
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/e2e-key-server/rest/handlers"
	"github.com/gorilla/mux"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
	google_protobuf3 "google/protobuf"
)

const (
	GET    = "GET"
	POST   = "POST"
	PUT    = "PUT"
	DELETE = "DELETE"

	// Source: http://www.regular-expressions.info/email.html
	EmailAddressRegEx = "[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?"
)

// Server holds internal state for the http rest server.
type Server struct {
	svr interface{} // Server instance.
	// TODO: v2 api server here.
	//creds Authenticator  // TODO define interface.
	rtr *mux.Router
}

// New creates a new rest server
// TODO(insert authenitcator as field param here
func New(svr interface{}) *Server {
	return &Server{svr, mux.NewRouter()}
}

// Serve starts the server loop.
func (s *Server) Serve(l net.Listener) {
	log.Fatal(http.Serve(l, nil))
}

func (s *Server) Handlers() *mux.Router {
	return s.rtr
}

// Method is the function type for http handlers. Context will contain security
// info. Input will be supplied via the appropriate procol buffer, and response
// will also be provided via a protocol buffer.
type Handler func(interface{}, context.Context, http.ResponseWriter, *http.Request, *handlers.HandlerInfo) error

// AddHandler tels the server to route request with path and method to m.
func (s *Server) AddHandler(rInfo handlers.RouteInfo, h Handler) {
	s.rtr.HandleFunc(rInfo.Path, s.handle(h, rInfo)).Methods(rInfo.Method)
}

func (s *Server) handle(h Handler, rInfo handlers.RouteInfo) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Build context.
		ctx := context.Background()
		// TODO insert authentication information.

		w.Header().Set("Content-Type", "application/json")
		if err := h(s.svr, ctx, w, r, rInfo.Initializer(rInfo)); err != nil {
			toHttpError(err, w)
		}
	}
}

func toHttpError(err error, w http.ResponseWriter) {
	switch grpc.Code(err) {
	case codes.OK:
	case codes.Canceled:
	case codes.Unknown:
	case codes.InvalidArgument:
	case codes.DeadlineExceeded:
	case codes.NotFound:
	case codes.AlreadyExists:
	case codes.PermissionDenied:
	case codes.Unauthenticated:
	case codes.ResourceExhausted:
	case codes.FailedPrecondition:
	case codes.Aborted:
	case codes.OutOfRange:
	case codes.Unimplemented:
	case codes.Internal:
	case codes.Unavailable:
	case codes.DataLoss:
	}
}

// Initialize HandlerInfo to be be able to call GetUser
func GetUser_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the proxy GetUser
	info.H = rInfo.Handler
	// Create a new GetUserRequest to be passed to the API handler
	info.Arg = new(v2pb.GetUserRequest)
	// Create a new function that parses URL parameters
	info.Parser = func(u *url.URL, arg *interface{}) error {
		// URL of format: /v1/users/{userid}, it cannot be any different format
		// otherwise Gorilla mux wouldn't have routed the request here
		components := strings.Split(strings.TrimLeft(u.Path, "/"), "/")
		if len(components) < len(strings.Split(strings.TrimLeft(rInfo.Path, "/"), "/")) {
			return grpc.Errorf(codes.InvalidArgument, "Invalid API url format")
		}

		in := (*arg).(*v2pb.GetUserRequest)
		// Parse User ID
		// components[2] is userId = email
		userId, err := parseUserId(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		m, _ := url.ParseQuery(u.RawQuery)
		// Parse time, use current time when the field is absent
		if val, ok := m["time"]; ok {
			t, err := parseTime(val[0])
			if err != nil {
				return err
			}
			in.Time = t
		}

		// Parse App ID
		if val, ok := m["appId"]; ok {
			in.AppId = val[0]
		}

		return nil
	}

	return info
}

// Parse RFC 3339 formated time strings and return a Timestamp instance
func parseTime(value string) (*google_protobuf3.Timestamp, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Invalid timestamp format")
	}
	result := new(google_protobuf3.Timestamp)
	result.Seconds = t.Unix()
	result.Nanos = int32(t.Nanosecond())
	return result, nil
}

// Parse an API string components, and verify that userId is a format-valid email address
// and return it
func parseUserId(components []string, index int) (string, error) {
	if index < 0 || index >= len(components) {
		return "", grpc.Errorf(codes.InvalidArgument, "User ID index is not in API path components")
	}

	userId := components[index]
	exp, err := regexp.Compile(EmailAddressRegEx)
	if err != nil {
		return "", err
	}
	if exp.MatchString(userId) {
		return userId, nil
	} else {
		return "", grpc.Errorf(codes.InvalidArgument, "Invalid User ID (email) format")
	}
}

// Actually calls proxy.GetUser. This function could be inline in GetUser_InitializeHandlerInfo
// but it is separated to allow better unit testing
func GetUser_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).GetUser(ctx, arg.(*v2pb.GetUserRequest))
	return &resp, err
}
