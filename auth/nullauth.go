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

// Package implements authenitcation mechanisms.
package auth

import (
	"golang.org/x/net/context"
)

const (
	testPrimaryUserEmail = "e2eshare.test@gmail.com"
)

//TODO: Implement OAuth authenticator
type NullAuth struct{}

// New returns a new authenticator.
func New() Authenticator {
	return &NullAuth{}
}

func (a *NullAuth) GetAuthenticatedEmail(ctx context.Context, scopes ...string) (string, error) {
	// TODO: implement real auth.
	return testPrimaryUserEmail, nil
}

func (a *NullAuth) CheckScopes(ctx context.Context, scopes ...string) error {
	// TODO: implement real auth.
	return nil
}
