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

// Package implements authenitcation mechanisms.
package auth

import (
	context "golang.org/x/net/context"
)

const (
	testPrimaryUserEmail = "test@gmail.com"
)

type Authenticator interface {
	// Extract an authenticated email from the context.
	GetAuthenticatedEmail(ctx context.Context) (string, error)
	// Verify that the call contains all the requested scopes.
	VerifyScopes(ctx context.Context, scopes []string) error
}

//TODO: Implement OAuth authenticator
type NullAuth struct {}

func New() Authenticator {
	return &NullAuth{}
}


func (a *NullAuth) GetAuthenticatedEmail(ctx context.Context) (string, error) {
	return testPrimaryUserEmail,  nil  // Fake auth for testing.
}

func (a *NullAuth) VerifyScopes(ctx context.Context, scopes []string) error {
	return nil
	//return grpc.Errorf(codes.Unimplemented, "Fake auth")
}
