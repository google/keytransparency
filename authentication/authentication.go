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

// Package authentication implements authentication mechanisms.
//
// This package is designed to be used by identity providers.
// OAuth2 Access tokens may be provided as authentication information, which can
// be resolved to userinformation and associated scopes on the backend.
//
// For demo purposes, we support OpenId Connect in implicit mode.
package authentication

import (
	"errors"

	"golang.org/x/net/context"
)

var (
	ErrMissingAuth = errors.New("auth: missing authentication header")
	ErrWrongUser   = errors.New("auth: email missmatch")
)

// Authenticator provides services to authenticate users.
type Authenticator interface {
	ValidateCreds(ctx context.Context, requiredUserID string) error
}
