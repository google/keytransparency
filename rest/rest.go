// Package rest converts REST HTTP requests into gRPC requests.
package rest

import (
	"log"
	"net"
	"net/http"

	"github.com/gdbelvin/key-transparency/proxy"
	"google.golang.org/grpc"

	proto "github.com/golang/protobuf/proto"
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
}

// New creates a new rest server
func New(proxy *proxy.Server) *Server {
	return &Server{grpc.NewServer(), proxy}
}

// Serve starts the server loop.
func (s *Server) Serve(l net.Listener) {
	log.Fatal(http.Serve(l, nil))
}

func (s *Server) RegisterService(sd *grpc.ServiceDesc, ss interface{}) {
	// addPaths adds server URLs to the mux.
	// TODO: parse paths from the proto.
}

/*
func (s *Server) AddResource(resource interface{}, string method, path string) {
	http.HandleFunc(path, s.Handle(resource))
	http.HandleFunc("/v1/user/{userid}", s.Handle)
	//TODO .Methods("GET")
}
*/

func (s *Server) errorToHttp(err error, w http.ResponseWriter) {
	//TODO: convert a go error into a standard http error
	//TODO: maybe use a custom error type that has a code.
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

type Method func(context.Context, proto.Message) (proto.Message, error)

/*
func (s *Server) Handle(f Method, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO figure out what method is being called.
		switch r.Method {
		case GET:
			if err := GetUser(); err != nil {
				errorToHttp(err)
			}
		default:
			http.Error(w, http.StatusMethodNotAllowed, "")
		}
	}
}
*/

func JsonToProto() {
}

func ProtoToJson() {
}

/*
func (s *Server) GetUser() error {
	// require auth.
	// TODO: Read from some configuration for which scopes to require.
	creds, err := s.creds.Validate(headers)
	if err != nil {
		// TODO fail
	}

	if !s.Auth([]string{}) {
		return errors.New("Auth failed")
	}
	// Convert json into protobuf
	ctx := context.Background()
	// TODO: generate a security context.
	// Call method
	resp, err := s.proxy.GetUser(ctx, req)
	if err != nil {
		return err
	}
	// Convert protobuf back into json
	json, err := ProtoToJson(resp)
	if err != nil {
		return err
	}
	// return json
}
*/
