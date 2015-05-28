// Package proxy converts v1 API requests into v2 API calls.
package proxy

import (
	"fmt"

	v1pb "github.com/gdbelvin/e2ekeys/proto"
	context "golang.org/x/net/context"
)

// Server holds internal state for the proxy server.
type Server struct {
}

// New creates a new instance of the proxy server.
func New() *Server {
	return &Server{}
}

// GetUser returns a user's keys.
func (s *Server) GetUser(ctx context.Context, in *v1pb.GetUserRequest) (*v1pb.User, error) {
	fmt.Println("GetUser Called!")
	return nil, nil
}
