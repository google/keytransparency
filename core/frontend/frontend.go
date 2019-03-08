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

// Package frontend implements the KeyTransaprencyFrontend service.
package frontend

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/tink"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/google/keytransparency/core/client"

	pb "github.com/google/keytransparency/core/api/v1/keytransparency_go_proto"
)

// PublicKeyGetter retrives a public key.
type PublicKeyGetter interface {
	PublicKey() *keyset.Handle
}

// Ensure that Frontend implements KeyTransparencyFrontendServer
var _ pb.KeyTransparencyFrontendServer = &Frontend{}

// Frontend implements KeyTransparencyFrontend.
type Frontend struct {
	Client  *client.Client
	Signers []tink.Signer
	PubKeys PublicKeyGetter
}

// QueueKeyUpdate signs an update and forwards it to the keyserver.
func (f *Frontend) QueueKeyUpdate(ctx context.Context, in *pb.QueueKeyUpdateRequest) (*empty.Empty, error) {
	if got, want := in.DirectoryId, f.Client.DirectoryID; got != want {
		return nil, status.Errorf(codes.InvalidArgument, "wrong directory_id: %v, want %v", got, want)
	}
	u := &client.User{
		UserID:         in.UserId,
		PublicKeyData:  in.KeyData,
		AuthorizedKeys: f.PubKeys.PublicKey(),
	}
	m, err := f.Client.CreateMutation(ctx, u)
	if err != nil {
		return nil, err
	}
	if err := f.Client.QueueMutation(ctx, m, f.Signers); err != nil {
		return nil, err
	}
	return &empty.Empty{}, nil
}
