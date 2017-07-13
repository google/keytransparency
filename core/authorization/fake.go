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

// Package authorization contains the authorization module implementation.
package authorization

import (
	"github.com/google/keytransparency/core/authentication"

	authzpb "github.com/google/keytransparency/core/proto/authorization"
)

type fakeAuthz struct {
}

// NewFake creates a new instance of the fake authorization module.
func NewFake() Authorization {
	return &fakeAuthz{}
}

// IsAuthorized always returns nil.
func (*fakeAuthz) IsAuthorized(sctx *authentication.SecurityContext, mapID, appID int64,
	userID string, permission authzpb.Permission) error {
	return nil
}
