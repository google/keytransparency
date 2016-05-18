// Copyright 2016 Google Inc. All Rights Reserved.
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

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/google/e2e-key-server/proto/security_e2ekeys"
	v1pb "github.com/google/e2e-key-server/proto/security_e2ekeys_v1"
)

const (
	pgpAppID = "pgp"
)

// Server holds internal state for the proxy server.
// TODO: replace proxy logic with a server side client instance.
type Server struct {
	s *keyserver.Server
}

// New creates a new instance of the proxy server.
func New(srv *keyserver.Server) *Server {
	return &Server{srv}
}

// GetEntry returns a user's profile.
// TODO: remove insecure GetEntry?
func (s *Server) GetEntry(ctx context.Context, in *pb.GetEntryRequest) (*pb.Profile, error) {
	result, err := s.s.GetEntry(ctx, in)
	if err != nil {
		return nil, err
	}

	// If result.Profile is empty, then the profile does not exist.
	if len(result.Profile) == 0 {
		return nil, grpc.Errorf(codes.NotFound, "Not found")
	}

	// Extract and returned the user profile from the resulted
	// GetEntryResponse.
	profile := new(pb.Profile)
	if err := proto.Unmarshal(result.Profile, profile); err != nil {
		return nil, grpc.Errorf(codes.Internal, "Provided profile cannot be parsed")
	}

	return profile, nil
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

	getEntryRequest := pb.GetEntryRequest{UserId: in.Search}
	profile, err := s.GetEntry(ctx, &getEntryRequest)
	if err != nil {
		return nil, err
	}

	// hkpGet only supports returning one key.
	if got, want := len(profile.GetKeys()), 1; got != want {
		return nil, grpc.Errorf(codes.Unimplemented, "Only a single key retrieval is supported")
	}

	// From here on, there is only one key in the key list.
	armoredKey, err := armorKey(profile.GetKeys()[pgpAppID])
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
func armorKey(key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, grpc.Errorf(codes.NotFound, "Missing pgp key")
	}
	armoredKey := bytes.NewBuffer(nil)
	w, err := armor.Encode(armoredKey, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot create HKP key armor encoder")
	}
	_, err = w.Write(key)
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "Cannot armor HKP key")
	}
	w.Close()
	return armoredKey.Bytes(), nil
}
