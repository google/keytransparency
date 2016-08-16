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

package keyserver

import (
	"bytes"
	"errors"
	"log"
	"strings"

	"github.com/golang/protobuf/ptypes"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	pb "github.com/google/key-transparency/proto/keytransparency_v1"
)

const (
	pgpAppID = "pgp"
)

var (
	errMissingKey = errors.New("Missing pgp key")
	errEncoder    = errors.New("Cannot create HKP key armor encoder")
	errArmor      = errors.New("Cannot armor HKP key")
)

// HkpLookup implements HKP pgp keys lookup.
func (s *Server) HkpLookup(ctx context.Context, in *pb.HkpLookupRequest) (*pb.HttpResponse, error) {
	switch in.Op {
	case "get":
		return s.hkpGet(ctx, in)
	default:
		return nil, grpc.Errorf(codes.Unimplemented, "op=%v is not implemented", in.Op)
	}
}

// HkpGet implements HKP pgp keys lookup for op=get.
func (s *Server) hkpGet(ctx context.Context, in *pb.HkpLookupRequest) (*pb.HttpResponse, error) {
	// Search by key index is not supported
	if strings.HasPrefix(in.Search, "0x") {
		return nil, grpc.Errorf(codes.Unimplemented, "Searching by key index are not supported")
	}

	getEntryRequest := pb.GetEntryRequest{UserId: in.Search}
	result, err := s.GetEntry(ctx, &getEntryRequest)
	if err != nil {
		log.Printf("Failed to retrieve entry: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Cannot retrieve entry")
	}
	if result.GetCommitted() == nil {
		return nil, grpc.Errorf(codes.NotFound, "Not found")
	}
	// Extract and returned the user profile from the resulted

	var profile pb.Profile
	if err := ptypes.UnmarshalAny(result.GetCommitted().Data, &profile); err != nil {
		log.Printf("Cannot unmarshal profile: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Provided profile cannot be parsed")
	}

	// hkpGet only supports returning one key.
	if got, want := len(profile.GetKeys()), 1; got != want {
		return nil, grpc.Errorf(codes.Unimplemented, "Only a single key retrieval is supported")
	}

	// From here on, there is only one key in the key list.
	armoredKey, err := armorKey(profile.GetKeys()[pgpAppID])
	if err != nil {
		log.Printf("Cannot armor key: %v", err)
		return nil, grpc.Errorf(codes.Internal, "Armor key failed")
	}

	out := pb.HttpResponse{Body: armoredKey}
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
		return nil, errMissingKey
	}
	armoredKey := bytes.NewBuffer(nil)
	w, err := armor.Encode(armoredKey, openpgp.PublicKeyType, nil)
	if err != nil {
		return nil, errEncoder
	}
	_, err = w.Write(key)
	if err != nil {
		return nil, errArmor
	}
	w.Close()
	return armoredKey.Bytes(), nil
}
