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

package keyserver

// validate performs correctness checking on each v2 message type.

import (
	"bytes"
	"fmt"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"

	proto "github.com/golang/protobuf/proto"
	v2pb "github.com/google/e2e-key-server/proto/v2"
)

// Maximum period of time to allow between CreationTime and server time.
const MaxClockDrift = 5 * time.Minute
const PGPAppID = "pgp"

var requiredScopes = []string{"https://www.googleapis.com/auth/userinfo.email"}

// validateEmail compares the given email against the one provided by GAIA.
func (s *Server) validateEmail(ctx context.Context, email string) error {
	if err := s.a.CheckScopes(ctx, requiredScopes...); err != nil {
		return err
	}
	verifiedEmail, err := s.a.GetAuthenticatedEmail(ctx, requiredScopes...)
	if err != nil {
		return err
	}

	if verifiedEmail != email {
		return grpc.Errorf(codes.PermissionDenied, "wrong user")
	}
	return nil
}

// validateKey verifies:
// - appID is present.
// - Key is valid for its format.
func (s *Server) validateKey(userID, appID string, key []byte) error {
	if appID == "" {
		return grpc.Errorf(codes.InvalidArgument, "Missing AppId")
	}
	if appID == PGPAppID {
		pgpUserID := fmt.Sprintf("<%v>", userID)
		if _, err := validatePGP(pgpUserID, bytes.NewBuffer(key)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) validateUpdateUserRequest(ctx context.Context, in *v2pb.UpdateUserRequest) error {
	// Validate proper authentication.
	if err := s.validateEmail(ctx, in.UserId); err != nil {
		return err
	}

	// TODO(cesarghali): validate SignedEntryUpdate.

	// Unmarshal user's profile.
	p := new(v2pb.Profile)
	if err := proto.Unmarshal(in.GetUpdate().Profile, p); err != nil {
		return grpc.Errorf(codes.InvalidArgument, "Cannot unmarshal profile")
	}

	if err := s.validateProfile(p, in.UserId); err != nil {
		return err
	}
	return nil
}

func (s *Server) validateProfile(p *v2pb.Profile, userID string) error {
	for appID, key := range p.GetKeys() {
		if err := s.validateKey(userID, appID, key); err != nil {
			return err
		}
	}
	return nil
}
