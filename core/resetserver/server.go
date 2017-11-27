// Copyright 2017 Google Inc. All Rights Reserved.
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

// Package resetserver implements the AccountResetService
package resetserver

import (
	"context"
	"fmt"

	"github.com/google/keytransparency/core/adminstorage"
	"github.com/google/keytransparency/core/authentication"
	"github.com/google/keytransparency/core/authorization"
	"github.com/google/keytransparency/core/crypto/signatures"
	"github.com/google/keytransparency/core/mutator"
	"github.com/google/keytransparency/core/transaction"
	"github.com/google/trillian"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gpb "github.com/google/keytransparency/core/proto/keytransparency_v1_grpc"
	pb "github.com/google/keytransparency/core/proto/keytransparency_v1_proto"
)

var maxBatchSize = 100

type server struct {
	auth    authentication.Authenticator
	authz   authorization.Authorization
	admin   adminstorage.Storage
	tmap    trillian.TrillianMapClient
	storage mutator.MutationStorage
	factory transaction.Factory
	signers []signatures.Signer
	// authorizedKeys []*tpb.PublicKey // Default set of authorized keys
}

// New returns an AccountResetService
func New() gpb.AccountRecoveryServiceClient {
	return &server{}
}

// CreateAccount creates one account
func (s *server) CreateAccount(ctx context.Context, in *pb.CreateAccountRequest) (*pb.CreateAccountResponse, error) {
	ret, err := s.BatchCreateAccount(ctx, &pb.BatchCreateAccountRequest{
		Accounts:               []*pb.Account{in.Account},
		AddAccountRecoveryKeys: in.AddAccountRecoveryKeys,
	})
	if err != nil {
		return nil, err
	}
	if got, want := len(ret.Errors), 1; got != want {
		return nil, fmt.Errorf("batch returned %v rows, want %v", got, want)
	}
	return nil, status.FromProto(ret[0])
}

// BatchCreateAccount
func (s *server) BatchCreateAccount(ctx context.Context, in *pb.BatchCreateAccountRequest) (*pb.BatchCreateAccountResponse, error) {
	// Authenticate Request.
	sctx, err := s.auth.ValidateCreds(ctx)
	if err != nil {
		return nil, err
	}
	if got, want := len(in.GetRequests()), maxBatchSize; got > want {
		return nil, status.Errorf(codes.InvalidArgument,
			"len(requests): %v, want < %v", got, want)
	}

	errors := make([]error, len(in.GetRequests()))

	for i, r := range in.GetRequests() {
		// TODO(gbelvin): Change IsAuthorized interface to accept domain as input.
		errors[i] = s.authz.IsAuthorized(0, in.GetAppId(), in.GetUserId, ppb.Permission_WRITE)
	}

	b, err := s.NewBatch(ctx, in.Accounts)
	if err != nil {
		return nil, err
	}
	// Assert that existing leaves are empty by not fetching existing data.
	b.SetData()
	b.SetAuthorizedKeys()
	// TODO (gbelvin): support adding a set of authorized keys to everything.
	b.SignMutations(signers)
	if err := b.SaveMutations(ctx); err != nil {
		return nil, err
	}
	// Trigger a sequence operation if the batch size is big enough?
	// Wait for new tree head
	// Verify new data entries
	if err := b.GetLeaves(ctx); err != nil {
		return nil, err
	}

	// Return results
	return &pb.BatchCreateAccountResponse{
		errors: nil,
	}, nil
}

func (s *server) waitForNewTreeHead(ctx context.Context) error {
	// Options
	// A) Poll the Trillian Log
	// B) Use channel for new roots
}
