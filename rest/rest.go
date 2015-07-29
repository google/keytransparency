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

// GetUser_InitializeHandlerInfo initializes and returns HandlerInfo preparing
// to call proxy.GetUser API.
func GetUser_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
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
		// Parse time, use current time when the field is absent.
		if val, ok := m["time"]; ok {
			t, err := parseTime(val[0])
			if err != nil {
				return err
			}
			in.Time = t
		}

		// Parse App ID.
		if val, ok := m["app_id"]; ok {
			in.AppId = val[0]
		}

		return nil
	}

	return info
}

// GetUser_RequestHandler calls proxy.GetUser and returns its results. An error
// will be returned if proxy.GetUser returns an error.
func GetUser_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).GetUser(ctx, arg.(*v2pb.GetUserRequest))
	return &resp, err
}

// CreateKey_InitializehandlerInfo initializes and return HandlerInfo preparing
// to call proxy.CreateKey API.
func CreateKey_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the proxy CreateKey.
	info.H = rInfo.Handler
	// Create a new CreateKeyRequest to be passed to the API handler.
	info.Arg = new(v2pb.CreateKeyRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.CreateKeyRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		// Parse CreateKeyRequest.SignedKey.Key.CreationTime manually.
		// In JSON it's a string in RFC3339 format, but in proto it
		// should be google_protobuf3.Timestamp. This should be done
		// before attempting JSON decoding.
		if err := parseJSON(r, "creation_time"); err != nil {
			return err
		}

		return nil
	}

	return info
}

// CreateKey_RequestHandler calls proxy.CreateKey and returns its results. An
// error will be returned if proxy.CreateKey returns an error.
func CreateKey_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).CreateKey(ctx, arg.(*v2pb.CreateKeyRequest))
	return &resp, err
}

// UpdateKey_InitializeHandlerInfo initializes and returns HandlerInfo
// preparing to call proxy.UpdateKey API.
func UpdateKey_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the proxy UpdateKey.
	info.H = rInfo.Handler
	// Create a new UpdateKeyRequest to be passed to the API handler.
	info.Arg = new(v2pb.UpdateKeyRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.UpdateKeyRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		// Parse Key ID; components[4] is keyId.
		keyId, err := parseURLComponent(components, rInfo.KeyIdIndex)
		if err != nil {
			return err
		}
		in.KeyId = keyId

		// Parse UpdateKeyRequest.SignedKey.Key.CreationTime manually.
		// In JSON it's a string in RFC3339 format, but in proto it
		// should be google_protobuf3.Timestamp. This should be done
		// before attempting JSON decoding.
		if err := parseJSON(r, "creation_time"); err != nil {
			return err
		}

		return nil
	}

	return info
}

// UpdateKey_RequestHandler calls proxy.UpdateKey and returns its results. An
// error will be returned if proxy.UpdateKey returns an error.
func UpdateKey_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).UpdateKey(ctx, arg.(*v2pb.UpdateKeyRequest))
	return &resp, err
}

// DeleteKey_InitializeHandlerInfo initializes and returns HandlerInfo
// preparing to call proxy.DeleteKey API.
func DeleteKey_InitializeHandlerInfo(rInfo handlers.RouteInfo) *handlers.HandlerInfo {
	info := new(handlers.HandlerInfo)
	// Set the API handler to call the proxy DeleteKey.
	info.H = rInfo.Handler
	// Create a new DeleteKeyRequest to be passed to the API handler.
	info.Arg = new(v2pb.DeleteKeyRequest)
	// Create a new function that parses URL parameters.
	info.Parser = func(r *http.Request, arg *interface{}) error {
		// Get URL components.
		components := strings.Split(strings.TrimLeft(r.URL.Path, "/"), "/")

		in := (*arg).(*v2pb.DeleteKeyRequest)
		// Parse User ID; components[2] is userId = email.
		userId, err := parseURLComponent(components, rInfo.UserIdIndex)
		if err != nil {
			return err
		}
		in.UserId = userId

		// Parse Key ID; components[4] is keyId.
		keyId, err := parseURLComponent(components, rInfo.KeyIdIndex)
		if err != nil {
			return err
		}
		in.KeyId = keyId

		return nil
	}

	return info
}

// DeleteKey_RequestHandler calls proxy.DeleteKey and returns its results. An
// error will be returned if proxy.DeleteKey returns an error.
func DeleteKey_RequestHandler(srv interface{}, ctx context.Context, arg interface{}) (*interface{}, error) {
	var resp interface{}
	resp, err := srv.(v1pb.E2EKeyProxyServer).DeleteKey(ctx, arg.(*v2pb.DeleteKeyRequest))
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
