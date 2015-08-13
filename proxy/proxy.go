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
	"bytes"
	"strings"

	"github.com/google/e2e-key-server/keyserver"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	v1pb "github.com/google/e2e-key-server/proto/v1"
	v2pb "github.com/google/e2e-key-server/proto/v2"
	context "golang.org/x/net/context"
)

const (
	hkpAppId = "pgp"
)

// Server holds internal state for the proxy server.
type Server struct {
	s *keyserver.Server
}

// New creates a new instance of the proxy server.
func New(svr *keyserver.Server) *Server {
	return &Server{svr}
}

// GetUser returns a user's profile.
func (s *Server) GetUser(ctx context.Context, in *v2pb.GetUserRequest) (*v2pb.Profile, error) {
	result, err := s.s.GetUser(ctx, in)
	if err != nil {
		return nil, err
	}

	// Extract and returned the user profile from the resulted
	// EntryProfileAndProof.
	p := new(v2pb.Profile)
	if err := proto.Unmarshal(result.Profile, p); err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "Provided profile cannot be parsed")
	}

	return p, nil
}

// HkpLookup implements HKP pgp keys lookup.
func (s *Server) HkpLookup(ctx context.Context, in *v1pb.HkpLookupRequest) (*v1pb.HttpResponse, error) {
	switch in.Op {
	case "get":
		return s.hkpGet(ctx, in)
	default:
		return nil, grpc.Errorf(codes.Unimplemented, "op=%v is not implemented", in.Op)
	}
}

// HkpGet implements HKP pgp keys lookup for op=get.
func (s *Server) hkpGet(ctx context.Context, in *v1pb.HkpLookupRequest) (*v1pb.HttpResponse, error) {
	// Search by key index is not supported
	if strings.HasPrefix(in.Search, "0x") {
		return nil, grpc.Errorf(codes.Unimplemented, "Searching by key index are not supported")
	}

	getUserRequest := v2pb.GetUserRequest{UserId: in.Search, AppId: hkpAppId}
	profile, err := s.GetUser(ctx, &getUserRequest)
	if err != nil {
		return nil, err
	}

	// hkpGet only supports returning one key.
	if got, want := len(profile.GetKeys()), 1; got != want {
		return nil, grpc.Errorf(codes.Unimplemented, "Only a single key retrieval is supported")
	}

	// From here on, there is only one key in the key list.
	armoredKey, err := armorKey(&v2pb.Key{AppId: hkpAppId, Key: profile.GetKeys()[hkpAppId]})
	if err != nil {
		return nil, err
	}

	out := v1pb.HttpResponse{Body: armoredKey}
	// Format output based on the provided options.
	out.ContentType = "text/plain"
	for _, option := range strings.Split(in.Options, ",") {
		if option == "mr" {
			out.ContentType = "application/pgp-keys"
		}
	}

	return &out, nil
}

// armorKey converts a Key of pgp type into an armored PGP key.
func armorKey(key *v2pb.Key) ([]byte, error) {
	if key == nil {
		return nil, grpc.Errorf(codes.NotFound, "key=nil")
	}
	if got, want := key.AppId, hkpAppId; got != want {
		return nil, grpc.Errorf(codes.NotFound, "key.AppId=%v, want %v", got, want)
	}

	armoredKey := bytes.NewBuffer(nil)
	w, err := armor.Encode(armoredKey, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, err
	}
	_, err = w.Write(key.Key)
	if err != nil {
		return nil, err
	}
	w.Close()
	return armoredKey.Bytes(), nil
}
