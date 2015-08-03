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
	"bytes"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
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
)

// Server holds internal state for the http rest server.
type Server struct {
	svr interface{} // Server instance.
	// TODO: v2 api server here.
	//creds Authenticator  // TODO define interface.
	rtr *mux.Router
}

// New creates a new rest server.
// TODO(insert authenitcator as field param here.
func New(svr interface{}) *Server {
	return &Server{svr, mux.NewRouter()}
}

// Serve starts the server loop.
func (s *Server) Serve(l net.Listener) {
	// If the second paramter (handler) is nil, DefaultServeMux is used.
	// We should use the gorilla mux router instead.
	log.Fatal(http.Serve(l, s.rtr))
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

// GetUserV1_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call proxy.GetUser API.
func GetUserV1_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the proxy GetUser.
	info.H = rInfo.Handler
	// Create a new GetUserRequest to be passed to the API handler.
	info.Arg = new(v2pb.GetUserRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.GetUserRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse Epoch. Epoch must be of type uint64.
		if val, ok := m["epoch"]; ok {
			if epoch, err := strconv.ParseInt(val[0], 10, 64); err != nil || epoch < 0 {
				return grpc.Errorf(codes.InvalidArgument, "Epoch must be uint64")
			} else {
				in.Epoch = uint64(epoch)
			}
		}

		// Parse App ID.
		if val, ok := m["app_id"]; ok {
			in.AppId = val[0]
		}

		return nil
	}

	return info
}

// GetUserV1_RequestHandler calls proxy.GetUser and returns its results. An error
// will be returned if proxy.GetUser returns an error.
func GetUserV1_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).GetUser(ctx, arg.(*v2pb.GetUserRequest))
	return &resp, err
}

// GetUserV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.GetUser API.
func GetUserV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver GetUser.
	info.H = rInfo.Handler
	// Create a new GetUserRequest to be passed to the API handler.
	info.Arg = new(v2pb.GetUserRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.GetUserRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse Epoch. Epoch must be of type uint64.
		if val, ok := m["epoch"]; ok {
			if epoch, err := strconv.ParseUint(val[0], 10, 64); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Epoch must be uint64")
			} else {
				in.Epoch = uint64(epoch)
			}
		}

		// Parse App ID.
		if val, ok := m["app_id"]; ok {
			in.AppId = val[0]
		}

		return nil
	}

	return info
}

// GetUserV2_RequestHandler calls keyserver.GetUser and returns its results. An error
// will be returned if keyserver.GetUser returns an error.
func GetUserV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).GetUser(ctx, arg.(*v2pb.GetUserRequest))
	return &resp, err
}

// ListUserHistoryV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.ListUserHistory API.
func ListUserHistoryV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver ListUserHistory.
	info.H = rInfo.Handler
	// Create a new ListUserHistoryRequest to be passed to the API handler.
	info.Arg = new(v2pb.ListUserHistoryRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.ListUserHistoryRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse StartEpoch. StartEpoch must be of type uint64.
		if val, ok := m["start_epoch"]; ok {
			if start_epoch, err := strconv.ParseUint(val[0], 10, 64); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Start Epoch must be uint64")
			} else {
				in.StartEpoch = uint64(start_epoch)
			}
		}

		// Parse PageSize. PageSize must be of type int32.
		if val, ok := m["page_size"]; ok {
			if page_size, err := strconv.ParseInt(val[0], 10, 32); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Page size must be int32")
			} else {
				in.PageSize = int32(page_size)
			}
		}

		return nil
	}

	return info
}

// ListUserHistoryV2_RequestHandler calls keyserver.ListUserHistory and returns its results. An error
// will be returned if keyserver.ListUserHistory returns an error.
func ListUserHistoryV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).ListUserHistory(ctx, arg.(*v2pb.ListUserHistoryRequest))
	return &resp, err
}

// UpdateUserV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.UpdateUser API.
func UpdateUserV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver UpdateUser.
	info.H = rInfo.Handler
	// Create a new UpdateUserRequest to be passed to the API handler.
	info.Arg = new(v2pb.UpdateUserRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.UpdateUserRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		return nil
	}

	return info
}

// UpdateUserV2_RequestHandler calls keyserver.UpdateUser and returns its results. An error
// will be returned if keyserver.UpdateUser returns an error.
func UpdateUserV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).UpdateUser(ctx, arg.(*v2pb.UpdateUserRequest))
	return &resp, err
}

// ListSEHV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.ListSEH API.
func ListSEHV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver ListSEH.
	info.H = rInfo.Handler
	// Create a new ListSEHRequest to be passed to the API handler.
	info.Arg = new(v2pb.ListSEHRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		in := (*arg).(*v2pb.ListSEHRequest)

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse StartEpoch. StartEpoch must be of type uint64.
		if val, ok := m["start_epoch"]; ok {
			if start_epoch, err := strconv.ParseUint(val[0], 10, 64); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Start Epoch must be uint64")
			} else {
				in.StartEpoch = uint64(start_epoch)
			}
		}

		// Parse PageSize. PageSize must be of type int32.
		if val, ok := m["page_size"]; ok {
			if page_size, err := strconv.ParseInt(val[0], 10, 32); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Page size must be int32")
			} else {
				in.PageSize = int32(page_size)
			}
		}

		return nil
	}

	return info
}

// ListSEHV2_RequestHandler calls keyserver.ListSEH and returns its results. An error
// will be returned if keyserver.ListSEH returns an error.
func ListSEHV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).ListSEH(ctx, arg.(*v2pb.ListSEHRequest))
	return &resp, err
}

// ListUpdateV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.ListUpdate API.
func ListUpdateV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver ListUpdate.
	info.H = rInfo.Handler
	// Create a new ListUpdateRequest to be passed to the API handler.
	info.Arg = new(v2pb.ListUpdateRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		in := (*arg).(*v2pb.ListUpdateRequest)

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse StartSequence. StartSequence must be of type uint64.
		if val, ok := m["start_sequence"]; ok {
			if start_sequence, err := strconv.ParseUint(val[0], 10, 64); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Start sequence must be uint64")
			} else {
				in.StartSequence = uint64(start_sequence)
			}
		}

		// Parse PageSize. PageSize must be of type int32.
		if val, ok := m["page_size"]; ok {
			if page_size, err := strconv.ParseInt(val[0], 10, 32); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Page size must be int32")
			} else {
				in.PageSize = int32(page_size)
			}
		}

		return nil
	}

	return info
}

// ListUpdateV2_RequestHandler calls keyserver.ListUpdate and returns its results. An error
// will be returned if keyserver.ListUpdate returns an error.
func ListUpdateV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).ListUpdate(ctx, arg.(*v2pb.ListUpdateRequest))
	return &resp, err
}

// ListStepsV2_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call keyserver.ListSteps API.
func ListStepsV2_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the keyserver ListSteps.
	info.H = rInfo.Handler
	// Create a new ListStepsRequest to be passed to the API handler.
	info.Arg = new(v2pb.ListStepsRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		in := (*arg).(*v2pb.ListStepsRequest)

		m, _ := url.ParseQuery(r.URL.RawQuery)
		// Parse StartSequence. StartSequence must be of type uint64.
		if val, ok := m["start_sequence"]; ok {
			if start_sequence, err := strconv.ParseUint(val[0], 10, 64); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Start sequence must be uint64")
			} else {
				in.StartSequence = uint64(start_sequence)
			}
		}

		// Parse PageSize. PageSize must be of type int32.
		if val, ok := m["page_size"]; ok {
			if page_size, err := strconv.ParseInt(val[0], 10, 32); err != nil {
				return grpc.Errorf(codes.InvalidArgument, "Page size must be int32")
			} else {
				in.PageSize = int32(page_size)
			}
		}

		return nil
	}

	return info
}

// ListStepsV2_RequestHandler calls keyserver.ListSteps and returns its results. An error
// will be returned if keyserver.ListSteps returns an error.
func ListStepsV2_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v2pb.E2EKeyServiceClient).ListSteps(ctx, arg.(*v2pb.ListStepsRequest))
	return &resp, err
}

// parseTime returns a google.protobuf.Timestamp instances generated by parsing
// a time string of RFC 3339 format. An error will be returned if the time
// string is not correctly formatted or cannot be parsed into a time object.
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

// parseTimeString returns marshaling google.protobuf.Timestamp into a JSON
// expression generated by parsing a time string of RFC 3339 format. An error
// will be returned if the time string is not correctly formatted or cannot be
// parsed into a time object.
func parseTimeString(value string) (string, error) {
	t, err := parseTime(value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("{\"seconds\": %v, \"nanos\": %v}", t.Seconds, t.Nanos), nil
}

// parseURLComponent returns component[index], or error if index of out of
// bounds.
func parseURLComponent(components []string, index int) (string, error) {
	if index < 0 || index >= len(components) {
		return "", grpc.Errorf(codes.InvalidArgument, "Index is not in API path components")
	}

	return components[index], nil
}

// parseJSON replaces all occurances of RFC 3339 formatted string timestamps
// into a format compatible with google.protobuf.Timestamo, i.e., {"seconds":
// <seconds>, "nanos": <nanos>}. This will allow the JSON decoder to decode the
// timestamp. The string timestamp is identified using its key specified in
// keyword. For example: {"creation_time": "2015-05-18T23:58:36.000Z"} will be
// replaced with {"creation_time": {"seconds": 1431993516, "nanos": 0}}.
// TODO(cesarghali): this function is not the best in terms of efficienty.
//                   Optimally use UnmarshalJSON to assist the JSON decoder.
func parseJSON(r *http.Request, keyword string) error {
	// Compiling the regular expression.
	timeRegexp := `("` + keyword + `"|` + keyword + `):[ ]*?("[a-zA-Z0-9:.\-]*")`
	rexp, err := regexp.Compile(timeRegexp)
	if err != nil {
		return grpc.Errorf(codes.Unknown, "Error while compiling regexp")
	}

	// Reading JSON body.
	inBuf := new(bytes.Buffer)
	inBuf.ReadFrom(r.Body)
	oldJSONBody := inBuf.String()
	newJSONBody := oldJSONBody

	// Replace the old JSON with the new one whenever this function
	// returns.
	defer func() {
		r.Body = jsonParserReader{bytes.NewBufferString(newJSONBody)}
	}()

	// Find all matchings based on the above regular expression. The rest
	// of this function would be much simpler and cleaner if this golang
	// issue is resolved: https://github.com/golang/go/issues/5690. Also,
	// I could have used regexp.ReplaceAllStringFunc but I would not be
	// able to return time parsing error since regexp.ReplaceAllStringFunc
	// does not allow to return an error.
	indices := rexp.FindAllStringSubmatchIndex(oldJSONBody, -1)
	if len(indices) > 0 {
		outBuf := new(bytes.Buffer)
		index := 0
		for _, v := range indices {
			if got, want := len(v), 6; got != want {
				return grpc.Errorf(codes.InvalidArgument, "JSON is not formatted correctly")
			}

			// Each v is of the following format [si1 ei1 si2 ei2
			// si3 ei3]. si1 and ei1 are start and end indices of the
			// matched string. si2 and ei2 are start and end indices
			// of the first submatched string; the keyword. si3 and
			// ei3 are the start and end indices of the second
			// submatched indices; the time string including the
			// double quotations.
			newJSONTime, err := parseTimeString(strings.Trim(oldJSONBody[v[4]:v[5]], "\""))
			if err != nil {
				return err
			}
			// Write unparsed JSON expression up until v[2]
			outBuf.WriteString(oldJSONBody[index:v[4]])
			// Write the new JSON time expression
			outBuf.WriteString(newJSONTime)
			// Mark JSON expression until v[3] as parsed
			index = v[5]
		}
		// Write the rest of the JSON expression
		outBuf.WriteString(oldJSONBody[index:])
		newJSONBody = outBuf.String()
	}

	return nil
}

type jsonParserReader struct {
	*bytes.Buffer
}

func (m jsonParserReader) Close() error {
	return nil
}
