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
	"golang.org/x/net/context"
)

// key is an unexported type to prevent collisions with keys in other packages.
type key int

// authKey is the key for security values in Contexts. Unexported.
var authKey = 0

type security struct {
	userID string
	scopes map[string]bool
}

type BasicAuth struct{}

// New returns a new authenticator.
func New() Authenticator {
	return &BasicAuth{}
}

func (a *BasicAuth) NewContext(userID string, scopes []string) context.Context {
	ctx := context.Background()
	set := make(map[string]bool)
	for _, scope := range scopes {
		set[scope] = true
	}
	return context.WithValue(ctx, authKey, security{userID, set})
}

func (a *BasicAuth) ValidateCreds(ctx context.Context, requiredUserID string, requiredScopes []string) bool {
	s, ok := ctx.Value(authKey).(security)
	if !ok {
		return false
	}
	if s.userID != requiredUserID {
		return false
	}
	for _, scope := range requiredScopes {
		if _, ok := s.scopes[scope]; !ok {
			return false
		}
	}
	return true
}
