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

package authentication

import (
	"context"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"

	grpc_auth "github.com/grpc-ecosystem/go-grpc-middleware/auth"
)

const fakeCredentialType string = "FakeCredential"

// FakeAuthFunc implements go-grpc-middleware/auth.AuthFunc
// FakeAuthFunc looks for a fake authentication token and puts a
// SecurityContext in the returned ctx.
func FakeAuthFunc(ctx context.Context) (context.Context, error) {
	token, err := grpc_auth.AuthFromMD(ctx, fakeCredentialType)
	if err != nil {
		return nil, err
	}

	return context.WithValue(ctx, securityContextKey, &SecurityContext{
		Email: token,
	}), nil
}

// GetFakeCredential returns fake PerRPCCredentials
func GetFakeCredential(userID string) credentials.PerRPCCredentials {
	return fakeCredential{userID: userID}
}

// fakeCredential implements credentials.PerRPCCredentials.
type fakeCredential struct {
	userID string
}

func (c fakeCredential) GetRequestMetadata(ctx context.Context, uri ...string) (map[string]string, error) {
	return map[string]string{
		"authorization": fakeCredentialType + " " + c.userID,
	}, nil
}

func (c fakeCredential) RequireTransportSecurity() bool {
	return false
}

// WithOutgoingFakeAuth returns a ctx with FakeAuth information for userID.
func WithOutgoingFakeAuth(ctx context.Context, userID string) context.Context {
	md, _ := GetFakeCredential(userID).GetRequestMetadata(ctx)
	return metadata.NewOutgoingContext(ctx, metadata.New(md))
}
