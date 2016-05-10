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
package authentication

import (
	"golang.org/x/net/context"
)

// Authenticator provides services to authenticate users.
type Authenticator interface {
	// Context returns an authenticated context for userID.
	// TODO: Replace with OAuth.
	NewContext(userID string, scopes []string) context.Context

	ValidateCreds(ctx context.Context, requiredUserID string, requiredScopes []string) bool
}
