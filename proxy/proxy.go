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
// Package proxy converts v1 API requests into v2 API calls.

package proxy

import (
	"fmt"

	v1pb "github.com/gdbelvin/key-server-transparency/proto"
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
